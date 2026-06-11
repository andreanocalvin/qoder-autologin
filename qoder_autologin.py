#!/usr/bin/env python3
"""
Qoder Auto-Login for 9router  (v3 — Batch + Headless + Portable)
Reverse-engineered from 9router v0.4.71 source code.

Features:
  - Google SSO auto-login (multi-language consent: EN, ID, etc.)
  - Batch mode from file (one email:password per line)
  - Concurrent processing (--concurrent N)
  - Headless or visible browser (--headless)
  - Auto-save to 9router SQLite database
  - Portable: works on any Windows machine with Python 3.8+

Usage:
  python qoder_autologin.py user@gmail.com:password
  python qoder_autologin.py --batch accounts.txt
  python qoder_autologin.py --batch accounts.txt --headless --concurrent 3
  python qoder_autologin.py --test user@gmail.com:password
"""

import argparse, asyncio, base64, hashlib, json, os, secrets, sqlite3, ssl, sys, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import aiohttp

# ── Qoder Constants (from 9router source) ─────────────────────────────
QODER_OPENAPI_BASE      = "https://openapi.qoder.sh"
QODER_API3_BASE         = "https://api3.qoder.sh"
QODER_LOGIN_URL         = "https://qoder.com/device/selectAccounts"
QODER_DEVICE_TOKEN_POLL = f"{QODER_OPENAPI_BASE}/api/v1/deviceToken/poll"
QODER_USERINFO_URL      = f"{QODER_OPENAPI_BASE}/api/v1/userinfo"

# ── 9router paths ──────────────────────────────────────────────────────
APPDATA = os.environ.get("APPDATA", "")
NINEROUTER_DATA_DIR     = Path(APPDATA) / "9router" if APPDATA else None
NINEROUTER_DB_PATH      = NINEROUTER_DATA_DIR / "db" / "data.sqlite" if NINEROUTER_DATA_DIR else None
NINEROUTER_MACHINE_ID   = NINEROUTER_DATA_DIR / "machine-id" if NINEROUTER_DATA_DIR else None

# ── Minimum 9router version ───────────────────────────────────────────
MIN_9ROUTER_VERSION = "0.4.71"

# ── SSL ────────────────────────────────────────────────────────────────
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# ── Global config (set by argparse) ───────────────────────────────────
HEADLESS = False
DEBUG_ENABLED = False


def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    pfx = {"INFO":"ℹ","OK":"✅","ERR":"❌","DBG":"🔍","WAIT":"⏳","SUM":"📊"}.get(level," ")
    text = f"[{ts}] {pfx} {msg}"
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        # Fallback for Windows cmd that doesn't support Unicode emojis
        pfx_ascii = {"INFO":"[i]","OK":"[+]","ERR":"[!]","DBG":"[*]","WAIT":"[~]","SUM":"[=]"}.get(level," ")
        print(f"[{ts}] {pfx_ascii} {msg}", flush=True)

def dbg(msg):
    if DEBUG_ENABLED: log(msg, "DBG")


def _short_error(err):
    """Truncate long Playwright/browser errors to a one-liner."""
    if not err:
        return ""
    err = str(err)

    # Known patterns → short labels
    patterns = [
        ("token_timeout", "token timeout"),
        ("google_sso_not_found", "Google SSO not found"),
        ("db_save_failed", "DB save failed"),
        ("Execution context was destroyed", "navigation interrupted"),
        ("Target page, context or browser has been closed", "browser closed"),
        ("Navigation timeout", "navigation timeout"),
    ]
    for pattern, label in patterns:
        if pattern in err:
            return label

    # Playwright timeout — extract first line
    if "Timeout" in err and "exceeded" in err:
        first_line = err.split("\n")[0].strip()
        # "Locator.press: Timeout 30000ms exceeded."
        return first_line

    # Generic: take first line, max 80 chars
    first_line = err.split("\n")[0].strip()
    return first_line[:80] + ("..." if len(first_line) > 80 else "")


# ══════════════════════════════════════════════════════════════════════
#  PKCE / helpers
# ══════════════════════════════════════════════════════════════════════
def generate_pkce_pair():
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge

def generate_nonce():
    return secrets.token_hex(16)

def get_machine_id():
    if NINEROUTER_MACHINE_ID and NINEROUTER_MACHINE_ID.exists():
        mid = NINEROUTER_MACHINE_ID.read_text().strip()
        if mid: return mid
    return str(uuid.uuid4())


def parse_version(v):
    """Parse version string '0.4.71' → tuple (0, 4, 71)"""
    try:
        return tuple(int(x) for x in v.strip().split("."))
    except:
        return (0, 0, 0)


def check_9router_version(min_version=None):
    """Check 9router installation and version. Returns (installed, version, ok)"""
    if min_version is None:
        min_version = MIN_9ROUTER_VERSION
    import subprocess

    # Method 1: npm global package.json
    try:
        result = subprocess.run(
            ["node", "-e",
             "try{const p=require(require('path').join("
             "require('child_process').execSync('npm root -g').toString().trim(),"
             "'9router','package.json'));console.log(p.version)}"
             "catch(e){console.log('NOT_FOUND')}"],
            capture_output=True, text=True, timeout=10,
        )
        version = result.stdout.strip()
        if version and version != "NOT_FOUND":
            ok = parse_version(version) >= parse_version(min_version)
            return True, version, ok
    except:
        pass

    # Method 2: check if DB exists at least
    if NINEROUTER_DB_PATH and NINEROUTER_DB_PATH.exists():
        return True, "unknown", False

    return False, None, False


# ══════════════════════════════════════════════════════════════════════
#  Phase 1 — Device Token Polling
# ══════════════════════════════════════════════════════════════════════
async def poll_device_token(nonce, verifier, timeout_sec=180, email=""):
    params = {"nonce": nonce, "verifier": verifier}
    start = time.time()
    poll_count = 0
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=_SSL_CTX)) as s:
        while time.time() - start < timeout_sec:
            poll_count += 1
            try:
                async with s.get(QODER_DEVICE_TOKEN_POLL, params=params,
                                 timeout=aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        data = await r.json()
                        if data.get("token"):
                            log(f"[{email}] Token received after {poll_count} polls ({time.time()-start:.0f}s)", "OK")
                            return data
                        else:
                            dbg(f"[{email}] Poll #{poll_count}: 200 but no token yet")
                    else:
                        dbg(f"[{email}] Poll #{poll_count}: status={r.status}")
            except Exception as e:
                dbg(f"[{email}] Poll #{poll_count} err: {e}")
            
            # Aggressive polling: 1s for first 20 attempts, then 2s after
            if poll_count < 20:
                await asyncio.sleep(1)
            else:
                await asyncio.sleep(2)
            
            # Periodic INFO log every ~20s so user knows polling is alive
            if poll_count % 15 == 0:
                elapsed = time.time() - start
                remaining = timeout_sec - elapsed
                log(f"[{email}] Still polling... ({poll_count} attempts, {elapsed:.0f}s elapsed, {remaining:.0f}s remaining)", "WAIT")
    log(f"[{email}] Poll timeout after {poll_count} attempts ({timeout_sec}s)", "ERR")
    return None


# ── Dialog auto-dismiss helper ───────────────────────────────────────
async def _auto_dismiss(dialog, email=""):
    """Auto-dismiss any browser dialog (alert, confirm, prompt, beforeunload)."""
    try:
        msg = dialog.message[:80] if dialog.message else ""
        dbg(f"[{email}] Dialog dismissed ({dialog.type}): {msg}")
        await dialog.dismiss()
    except Exception as e:
        dbg(f"[{email}] Dialog dismiss error: {e}")


# ══════════════════════════════════════════════════════════════════════
#  Phase 2 — Browser Automation
# ══════════════════════════════════════════════════════════════════════
async def automate_login(email, password, nonce, code_challenge, machine_id):
    from playwright.async_api import async_playwright

    auth_url = f"{QODER_LOGIN_URL}?" + urlencode({
        "challenge": code_challenge,
        "challenge_method": "S256",
        "machine_id": machine_id,
        "nonce": nonce,
    })

    log(f"[{email}] Opening login page...")
    dbg(f"URL: {auth_url[:120]}...")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=HEADLESS,
            args=[
                # ── Anti-detection flags ──
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-infobars",
                # Block "X wants to access your local network" prompt
                "--disable-features=PrivateNetworkAccessRespectPreflightResults,"
                    "PrivateNetworkAccessSendPreflights,"
                    "BlockInsecurePrivateNetworkRequests,"
                    "PrivateNetworkAccessPromptForUnsureBlocked,"
                    "TranslateUI,OptimizationHints",
            ],
        )
        ctx = await browser.new_context(
            viewport={"width": 500, "height": 700},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        )
        # ── Stealth script: hide Playwright fingerprints ──
        await ctx.add_init_script("""
            // Hide webdriver property
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            // Fake plugins (real Chrome has at least one)
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            // Fake languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
            // Chrome runtime
            window.chrome = { runtime: {} };
            // Permissions API
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) =>
                parameters.name === 'notifications'
                    ? Promise.resolve({state: Notification.permission})
                    : originalQuery(parameters);
            // WebGL vendor
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) return 'Intel Inc.';
                if (parameter === 37446) return 'Intel Iris OpenGL Engine';
                return getParameter.apply(this, arguments);
            };
        """)

        page = await ctx.new_page()

        # ── Auto-dismiss ALL browser dialogs (alert, confirm, prompt, beforeunload) ──
        page.on("dialog", lambda d: asyncio.ensure_future(_auto_dismiss(d, email)))

        page.set_default_timeout(30000)

        state = {"login_done": False, "error": None}

        try:
            await page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
            await asyncio.sleep(2)
            url = page.url
            log(f"[{email}] Page: {url[:80]}...")

            if "sign-in" in url or "users" in url:
                sso_found = await _handle_signin_page(page, email, password)

                if not sso_found:
                    log(f"[{email}] Aborting — Google SSO not available", "ERR")
                    state["error"] = "google_sso_not_found"
                else:
                    for i in range(90):
                        await asyncio.sleep(1)
                        try: url = page.url
                        except: break

                        if "selectAccounts" in url:
                            log(f"[{email}] Redirected to selectAccounts!", "OK")
                            sa_ok = await _handle_select_accounts(page, email)
                            if not sa_ok:
                                log(f"[{email}] selectAccounts click may have failed — token might not arrive", "ERR")
                            state["login_done"] = True
                            break
                        if any(x in url for x in ("callback","success","authorized")):
                            log(f"[{email}] Login successful!", "OK")
                            state["login_done"] = True
                            break
                        if "sign-in" in url and i > 15:
                            err = await _get_page_error(page)
                            if err:
                                log(f"[{email}] Page error: {err}", "ERR")
                                state["error"] = err

            elif "selectAccounts" in url:
                sa_ok = await _handle_select_accounts(page, email)
                if not sa_ok:
                    log(f"[{email}] selectAccounts click may have failed — token might not arrive", "ERR")
                state["login_done"] = True
            else:
                log(f"[{email}] Unexpected page: {url}", "ERR")

            if state["login_done"]:
                log(f"[{email}] Login flow complete. Closing browser...", "WAIT")
                # Brief wait for server to process authorization (no need to wait long)
                await asyncio.sleep(1)

        except Exception as e:
            log(f"[{email}] Browser error: {e}", "ERR")
            state["error"] = str(e)
        finally:
            await asyncio.sleep(1)
            await browser.close()

    return state


# ── Sign-in dispatcher ────────────────────────────────────────────────
async def _handle_signin_page(page, email, password):
    """Returns True if Google SSO was found and clicked, False otherwise."""
    log(f"[{email}] Detecting login method...")
    # Brief wait for page render (shorter for visible mode)
    await asyncio.sleep(1 if not HEADLESS else 2)

    # Retry Google SSO detection multiple times (headless may need more time)
    for attempt in range(5):
        if attempt > 0:
            dbg(f"[{email}] Google SSO retry #{attempt+1}...")
            await asyncio.sleep(1 if not HEADLESS else 2)

        if await _try_google_sso(page):
            log(f"[{email}] Google SSO detected. Handling Google login...", "OK")
            await _handle_google_login(page, email, password)
            return True

    # Qoder ONLY supports Google SSO — no direct email/password fallback
    log(f"[{email}] Google SSO button NOT found after 5 attempts!", "ERR")
    log(f"[{email}] Qoder only supports Google SSO login.", "ERR")
    # Try to get page info for debugging
    try:
        title = await page.title()
        url = page.url
        dbg(f"[{email}] Page title: {title}, URL: {url[:100]}")
        # Screenshot for debugging headless issues
        if HEADLESS:
            ss_path = f"debug_sso_{email.split('@')[0]}.png"
            await page.screenshot(path=ss_path)
            dbg(f"[{email}] Debug screenshot saved: {ss_path}")
    except:
        pass
    return False


# ── Google SSO ────────────────────────────────────────────────────────
async def _try_google_sso(page):
    google_selectors = [
        'button:has-text("Google")', 'a:has-text("Google")',
        '[class*="google" i]', 'button:has-text("Sign in with Google")',
        'a:has-text("Sign in with Google")', 'button[data-provider="google"]',
        '[aria-label*="Google" i]', 'img[alt*="Google" i]',
        'div:has-text("Google")', '[href*="google"]',
        'button:has-text("google")', 'a:has-text("google")',
        'span:has-text("Google")', 'span:has-text("google")',
    ]
    for sel in google_selectors:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=1000):
                await el.click(force=True)
                dbg(f"Google SSO clicked via: {sel}")
                # Shorter wait for visible mode, longer for headless
                await asyncio.sleep(1.5 if not HEADLESS else 2.5)
                return True
        except:
            continue
    # JS fallback — search all clickable elements for "google" text
    try:
        clicked = await page.evaluate("""() => {
            const els = document.querySelectorAll(
                'button, a, div[role="button"], span[role="button"], ' +
                '[onclick], [class*="btn"], [class*="button"], [class*="social"], ' +
                '[class*="oauth"], [class*="provider"], [class*="sso"]'
            );
            for (const el of els) {
                const txt = (el.textContent || el.innerText || el.getAttribute('aria-label') || '').toLowerCase();
                if (txt.includes('google')) {
                    // Scroll into view first (helps headless)
                    el.scrollIntoView({block: 'center'});
                    el.click();
                    return 'clicked: ' + (el.tagName + ':' + txt.trim().substring(0, 30));
                }
            }
            // Also check images with Google-related alt/src
            const imgs = document.querySelectorAll('img');
            for (const img of imgs) {
                const alt = (img.alt || '').toLowerCase();
                const src = (img.src || '').toLowerCase();
                if (alt.includes('google') || src.includes('google')) {
                    const parent = img.closest('button, a, [role="button"]') || img;
                    parent.scrollIntoView({block: 'center'});
                    parent.click();
                    return 'clicked img: ' + alt.substring(0, 30);
                }
            }
            return null;
        }""")
        if clicked:
            dbg(f"Google SSO JS fallback: {clicked}")
            await asyncio.sleep(3)
            return True
    except:
        pass
    return False


# ── Google Login ──────────────────────────────────────────────────────
async def _handle_google_login(page, email, password):
    log(f"[{email}] On Google login page. Automating...")

    for attempt in range(90):
        try:
            url = page.url
        except:
            log(f"[{email}] Page closed/navigated away", "OK")
            return

        if "accounts.google.com" not in url and "accounts.google.co" not in url:
            log(f"[{email}] Left Google. Now at: {url[:60]}", "OK")
            return

        # ── Email step ──
        try:
            email_visible = await page.evaluate("""() => {
                const el = document.querySelector('#identifierId');
                return el && el.offsetParent !== null;
            }""")
        except:
            email_visible = False
            await asyncio.sleep(1)
            continue

        if email_visible:
            dbg(f"[{email}] Filling Google email...")
            loc = page.locator("#identifierId").first
            await loc.click(force=True)
            await asyncio.sleep(0.2)
            await loc.press("Control+a")
            await loc.press("Backspace")
            await loc.press_sequentially(email, delay=40)
            await asyncio.sleep(0.3)
            await page.evaluate("""() => {
                const btn = document.querySelector('#identifierNext button');
                if (btn) btn.click();
            }""")
            # Wait for password field to appear (confirms email step passed)
            for _w in range(10):
                await asyncio.sleep(0.5)
                try:
                    pwd_check = await page.evaluate("""() => {
                        for (const el of document.querySelectorAll(
                                'input[name="Passwd"], input[type="password"]')) {
                            if (el.offsetParent !== null) return true;
                        }
                        return false;
                    }""")
                    if pwd_check:
                        break
                except:
                    pass
            await asyncio.sleep(0.5)
            continue

        # ── Password step ──
        try:
            pwd_visible = await page.evaluate("""() => {
                for (const el of document.querySelectorAll(
                        'input[name="Passwd"], input[type="password"]')) {
                    if (el.offsetParent !== null) return true;
                }
                return false;
            }""")
        except:
            pwd_visible = False
            await asyncio.sleep(1)
            continue

        if pwd_visible:
            dbg(f"[{email}] Filling Google password...")
            loc = page.locator('input[name="Passwd"]').first
            try:
                if await loc.count() == 0 or not await loc.is_visible():
                    loc = page.locator('input[type="password"]').first
            except:
                loc = page.locator('input[type="password"]').first
            await loc.click(force=True)
            await asyncio.sleep(0.2)
            await loc.press("Control+a")
            await loc.press("Backspace")
            await loc.press_sequentially(password, delay=30)
            await asyncio.sleep(0.2)
            await page.evaluate("""() => {
                const btn = document.querySelector('#passwordNext button');
                if (btn) btn.click();
            }""")
            try:
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
            except:
                pass
            await asyncio.sleep(2)
            continue

        # ── Consent / Agreement / Speedbump screens ──
        try:
            consent_clicked = await page.evaluate("""() => {
                // Priority 1: Known IDs
                const knownIds = ['confirm', 'submit_approve_access', 'approve_button',
                                 'next', 'identifierNext', 'passwordNext'];
                for (const id of knownIds) {
                    const el = document.getElementById(id);
                    if (el && el.offsetParent !== null) {
                        el.click(); return 'clicked id: ' + id;
                    }
                }
                // Priority 2: Known names
                const knownNames = ['confirm', 'continue', 'approve', 'accept'];
                for (const name of knownNames) {
                    const el = document.querySelector(`[name="${name}"]`);
                    if (el && el.offsetParent !== null) {
                        el.click(); return 'clicked name: ' + name;
                    }
                }
                // Priority 3: Text matching (multi-language)
                const buttons = document.querySelectorAll(
                    'button, [role="button"], span[role="button"], input[type="submit"], ' +
                    'span.VfPpkd-vQzf8d, div.VfPpkd-RLmnJb, [jsname="V67aGc"]'
                );
                const consentTexts = [
                    'i understand', 'i agree', 'agree', 'allow', 'continue', 'next',
                    'approve', 'confirm', 'accept', 'got it', 'accept all', 'done',
                    'i accept', 'accept & continue',
                    'saya mengerti', 'saya setuju', 'setuju', 'lanjutkan', 'terima',
                    'izinkan', 'konfirmasi', 'mengerti', 'oke', 'ya'
                ];
                for (const btn of buttons) {
                    const txt = (btn.textContent || btn.value || '').toLowerCase().trim();
                    if (consentTexts.some(t => txt.includes(t) || txt === t)) {
                        btn.click();
                        if (btn.tagName === 'SPAN' && btn.parentElement && btn.parentElement.tagName === 'BUTTON') {
                            btn.parentElement.click();
                        }
                        return 'clicked text: ' + txt;
                    }
                }
                // "Advanced" link
                const advEl = document.querySelector('#advancedButton') ||
                              document.querySelector('[id*="advanced"]');
                if (advEl) { advEl.click(); return 'clicked: advanced'; }
                for (const el of document.querySelectorAll('a, button, span')) {
                    const t = (el.textContent || '').toLowerCase();
                    if (t.includes('advanced') || t.includes('lanjutan')) {
                        el.click(); return 'clicked: advanced (text)';
                    }
                }
                return null;
            }""")
        except Exception:
            consent_clicked = None

        if consent_clicked:
            dbg(f"[{email}] Consent: {consent_clicked}")
            await asyncio.sleep(1.5)
            if "advanced" in str(consent_clicked):
                await asyncio.sleep(1)
                try:
                    unsafe_clicked = await page.evaluate("""() => {
                        const links = document.querySelectorAll('a, button, [role="button"]');
                        for (const el of links) {
                            const t = (el.textContent || '').toLowerCase();
                            if (t.includes('go to') || t.includes('unsafe') || t.includes('proceed')) {
                                el.click(); return 'clicked: ' + t.trim().substring(0, 40);
                            }
                        }
                        return null;
                    }""")
                    if unsafe_clicked:
                        dbg(f"[{email}] Unsafe link: {unsafe_clicked}")
                        await asyncio.sleep(2)
                except:
                    pass
            continue

        # ── Choose account page ──
        try:
            account_clicked = await page.evaluate("""() => {
                const accounts = document.querySelectorAll('[data-identifier], [data-email]');
                if (accounts.length > 0) { accounts[0].click(); return 'picked first account'; }
                return null;
            }""")
            if account_clicked:
                dbg(f"[{email}] Google account: {account_clicked}")
                await asyncio.sleep(2)
                continue
        except:
            pass

        await asyncio.sleep(1)

    log(f"[{email}] Google login timed out (90s)", "ERR")


# ── Qoder direct Email+Password ───────────────────────────────────────
async def _handle_qoder_password_login(page, email, password):
    log(f"[{email}] Filling Qoder login form...")
    email_selectors = [
        'input[placeholder*="email" i]', 'input[type="email"]',
        'input[name="email"]', 'input[placeholder*="mail" i]',
        'input[id*="email" i]', '.ant-input[type="text"]',
    ]
    pwd_selectors = [
        'input[type="password"]', 'input[name="password"]',
        'input[placeholder*="password" i]', '.ant-input-password input',
    ]
    submit_selectors = [
        'button[type="submit"]', 'button:has-text("Sign in")',
        'button:has-text("Log in")', 'button:has-text("Login")',
        '.ant-btn-primary', 'button[class*="submit" i]',
    ]

    for sel in email_selectors:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=2000):
                await el.click(); await el.fill("")
                await el.press_sequentially(email, delay=50)
                break
        except: continue
    else:
        await page.evaluate(f"""(email) => {{
            const inputs = document.querySelectorAll('input');
            for (const inp of inputs) {{
                if (inp.type==='email'||inp.type==='text'||inp.placeholder?.toLowerCase().includes('email')) {{
                    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(inp, email);
                    inp.dispatchEvent(new Event('input',{{bubbles:true}}));
                    inp.dispatchEvent(new Event('change',{{bubbles:true}}));
                    return;
                }}
            }}
        }}""", email)

    await asyncio.sleep(0.5)
    for sel in pwd_selectors:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=2000):
                await el.click(); await el.fill("")
                await el.press_sequentially(password, delay=60)
                break
        except: continue

    await asyncio.sleep(0.5)

    has_captcha = await page.evaluate("""() => {
        return !!document.querySelector(
            '#aliyunCaptcha-sliding, .aliyunCaptcha-btn, [class*="captcha" i], iframe[src*="captcha"]'
        );
    }""")
    if has_captcha:
        log(f"[{email}] CAPTCHA detected! Waiting for auto-verify...", "WAIT")
        for i in range(20):
            done = await page.evaluate("""() => {
                const ok = document.querySelector('.aliyunCaptcha-success, [class*="captcha"][class*="success"]');
                if (ok) return true;
                const btn = document.querySelector('#aliyunCaptcha-btn, .aliyunCaptcha-btn');
                if (btn && btn.style.display === 'none') return true;
                return false;
            }""")
            if done:
                log(f"[{email}] CAPTCHA auto-verified!", "OK")
                break
            await asyncio.sleep(1)
        else:
            log(f"[{email}] CAPTCHA may need manual solve. Waiting 30s...", "WAIT")
            await asyncio.sleep(30)

    await asyncio.sleep(0.5)
    for sel in submit_selectors:
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=2000):
                await el.click()
                log(f"[{email}] Login submitted!")
                await asyncio.sleep(2)
                return
        except: continue
    await page.keyboard.press("Enter")
    await asyncio.sleep(2)


# ── Select Accounts page ──────────────────────────────────────────────
async def _handle_select_accounts(page, email=""):
    """Handle the Qoder selectAccounts page with retry + diagnostics.
    
    This page appears after Google SSO succeeds. In most cases, the authorization
    is automatic and the page just shows "Sign in success" / "You're all set!"
    with no buttons to click. We detect this and return immediately.
    """
    # Wait for page to settle
    await asyncio.sleep(1)

    # ── Quick check: is this already a success page? (no action needed) ──
    try:
        page_text = await page.evaluate("() => document.body ? document.body.innerText.substring(0, 500) : ''")
    except:
        page_text = ""
    
    success_indicators = [
        "sign in success", "you're all set", "all set!",
        "begin your ai coding", "return to qoder",
        "successfully signed in", "login successful",
        "authorized successfully",
    ]
    page_text_lower = page_text.lower()
    
    if any(indicator in page_text_lower for indicator in success_indicators):
        log(f"[{email}] selectAccounts: Already authorized! (success page detected)", "OK")
        return True

    log(f"[{email}] Handling selectAccounts page...", "WAIT")

    for attempt in range(3):
        if attempt > 0:
            log(f"[{email}] selectAccounts retry #{attempt+1}...", "WAIT")
            await asyncio.sleep(2)

        # Wait for page to settle
        await asyncio.sleep(2)

        try:
            result = await page.evaluate("""() => {
                const info = { clicked: false, method: '', buttons: [], allText: '' };

                // Collect all visible button/link text for diagnostics
                const allClickable = document.querySelectorAll(
                    'button, a, [role="button"], [role="link"], input[type="submit"]'
                );
                info.buttons = Array.from(allClickable).slice(0, 20).map(el => ({
                    tag: el.tagName,
                    text: (el.textContent || el.value || '').trim().substring(0, 60),
                    visible: el.offsetParent !== null,
                    classes: (el.className || '').substring(0, 80),
                }));
                info.allText = document.body ? document.body.innerText.substring(0, 500) : '';

                // ── Strategy 1: Known action keywords (original + expanded) ──
                const actionTexts = [
                    'select', 'continue', 'authorize', 'confirm', 'allow',
                    'grant', 'approve', 'accept', 'sign in', 'log in',
                    'get started', 'proceed', 'next', 'ok',
                    // Indonesian
                    'pilih', 'lanjutkan', 'setujui', 'izinkan', 'konfirmasi',
                ];
                for (const btn of allClickable) {
                    if (btn.offsetParent === null) continue;
                    const t = (btn.textContent || btn.value || '').toLowerCase().trim();
                    if (actionTexts.some(kw => t.includes(kw))) {
                        btn.click();
                        info.clicked = true;
                        info.method = 'action-text: ' + t.substring(0, 50);
                        return info;
                    }
                }

                // ── Strategy 2: Click first account/profile card ──
                const accountEls = document.querySelectorAll(
                    '[class*="account"], [class*="user"], [class*="profile"], ' +
                    '[class*="card"], [class*="item"], [class*="option"]'
                );
                for (const el of accountEls) {
                    if (el.offsetParent === null) continue;
                    // Make sure it's not just a wrapper — check it has meaningful content
                    const txt = (el.textContent || '').trim();
                    if (txt.length > 2 && txt.length < 200) {
                        el.click();
                        info.clicked = true;
                        info.method = 'account-card: ' + txt.substring(0, 50);
                        return info;
                    }
                }

                // ── Strategy 3: Any visible button (last resort) ──
                for (const btn of allClickable) {
                    if (btn.offsetParent === null) continue;
                    const t = (btn.textContent || btn.value || '').trim();
                    if (t.length > 0) {
                        btn.click();
                        info.clicked = true;
                        info.method = 'first-visible-btn: ' + t.substring(0, 50);
                        return info;
                    }
                }

                return info;
            }""")
        except Exception as e:
            log(f"[{email}] selectAccounts JS error: {e}", "ERR")
            continue

        if result and result.get("clicked"):
            log(f"[{email}] selectAccounts: {result['method']}", "OK")
            # Wait for page to navigate/process after click
            await asyncio.sleep(3)
            return True

        # Not clicked — log diagnostics for debugging
        if result:
            btn_summary = [f"{b['tag']}:'{b['text'][:30]}'" for b in (result.get('buttons') or []) if b.get('visible')][:8]
            log(f"[{email}] selectAccounts: no matching button found (attempt {attempt+1}/3)", "ERR")
            log(f"[{email}] Visible buttons: {btn_summary}", "ERR")
            dbg(f"[{email}] Page text: {(result.get('allText') or '')[:200]}")

        # Screenshot for debugging (always save, not just headless)
        try:
            ss_path = f"debug_selectAccounts_{email.split('@')[0]}_a{attempt+1}.png"
            await page.screenshot(path=ss_path)
            log(f"[{email}] Screenshot saved: {ss_path}", "DBG" if attempt < 2 else "ERR")
        except:
            pass

    log(f"[{email}] selectAccounts: FAILED after 3 attempts — token may not be issued!", "ERR")
    log(f"[{email}] Check the debug_selectAccounts_*.png screenshots for clues.", "ERR")
    return False


# ── Page error extractor ──────────────────────────────────────────────
async def _get_page_error(page):
    try:
        return await page.evaluate("""() => {
            const el = document.querySelector(
                '.ant-form-item-explain-error, .error-message, [class*="error"]'
            );
            return el ? el.textContent.trim() : null;
        }""")
    except:
        return None


# ══════════════════════════════════════════════════════════════════════
#  Phase 3 — Save to 9router DB
# ══════════════════════════════════════════════════════════════════════
def get_existing_qoder_emails():
    """Get set of existing Qoder emails from 9router DB."""
    if not NINEROUTER_DB_PATH or not NINEROUTER_DB_PATH.exists():
        return set()
    try:
        conn = sqlite3.connect(str(NINEROUTER_DB_PATH))
        c = conn.cursor()
        c.execute("SELECT LOWER(email) FROM providerConnections WHERE provider='qoder' AND email IS NOT NULL")
        emails = {row[0].lower() for row in c.fetchall()}
        conn.close()
        return emails
    except Exception as e:
        dbg(f"Failed to read existing emails: {e}")
        return set()


def save_to_9router_db(email, display_name, access_token, refresh_token,
                       expires_at, user_id, machine_id, org_id=""):
    if not NINEROUTER_DB_PATH or not NINEROUTER_DB_PATH.exists():
        log(f"9router DB not found at {NINEROUTER_DB_PATH}", "ERR")
        log("Make sure 9router is installed and has been run at least once.", "ERR")
        return False

    now = datetime.now(timezone.utc).isoformat()
    conn_id = str(uuid.uuid4())

    data = {
        "displayName": display_name or email.split("@")[0],
        "accessToken": access_token,
        "refreshToken": refresh_token or "",
        "expiresAt": expires_at,
        "testStatus": "active",
        "expiresIn": 2591997,
        "providerSpecificData": {
            "authMethod": "device",
            "userId": user_id or "",
            "machineId": machine_id,
            "organizationId": org_id or "",
        },
    }

    try:
        conn = sqlite3.connect(str(NINEROUTER_DB_PATH))
        c = conn.cursor()
        c.execute("SELECT id FROM providerConnections WHERE provider='qoder' AND email=?",
                  (email,))
        existing = c.fetchone()

        if existing:
            c.execute("""UPDATE providerConnections
                         SET data=?, name=?, updatedAt=?, isActive=1
                         WHERE id=?""",
                      (json.dumps(data), display_name or email, now, existing[0]))
            log(f"[{email}] Updated existing connection", "OK")
        else:
            c.execute("SELECT COALESCE(MAX(priority),0)+1 FROM providerConnections WHERE provider='qoder'")
            pri = c.fetchone()[0]
            c.execute("""INSERT INTO providerConnections
                         (id, provider, authType, name, email, priority, isActive, data, createdAt, updatedAt)
                         VALUES (?, 'qoder', 'oauth', ?, ?, ?, 1, ?, ?, ?)""",
                      (conn_id, display_name or email, email, pri, json.dumps(data), now, now))
            log(f"[{email}] Created new connection", "OK")

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        log(f"[{email}] DB error: {e}", "ERR")
        return False


# ══════════════════════════════════════════════════════════════════════
#  Phase 4 — Fetch user info
# ══════════════════════════════════════════════════════════════════════
async def fetch_user_info(access_token):
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=_SSL_CTX)) as s:
            async with s.get(QODER_USERINFO_URL, headers=headers,
                             timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    return await r.json()
    except:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════
#  Process single account
# ══════════════════════════════════════════════════════════════════════
async def process_account(email, password, test_only=False):
    tag = "[TEST] " if test_only else ""
    log(f"\n{'='*50}\n{tag}{email}\n{'='*50}")
    start_time = time.time()

    verifier, challenge = generate_pkce_pair()
    nonce = generate_nonce()
    mid = get_machine_id()

    poll_task = asyncio.create_task(poll_device_token(nonce, verifier, 180, email))
    result = await automate_login(email, password, nonce, challenge, mid)

    if result.get("error") and not result.get("login_done"):
        log(f"[{email}] Login failed: {result['error']}", "ERR")
        poll_task.cancel()
        return {"success": False, "email": email, "error": result["error"]}

    # Check if token already ready (fast path)
    if poll_task.done():
        token_data = poll_task.result()
        if token_data and token_data.get("token"):
            log(f"[{email}] Token already ready!", "OK")
        else:
            log(f"[{email}] Waiting for device token...", "WAIT")
    else:
        log(f"[{email}] Waiting for device token...", "WAIT")
        token_data = await poll_task

    if not token_data or not token_data.get("token"):
        log(f"[{email}] Token timeout!", "ERR")
        return {"success": False, "email": email, "error": "token_timeout"}

    at = token_data["token"]
    rt = token_data.get("refreshToken", "")
    log(f"[{email}] Got token: {at[:20]}...", "OK")

    info = await fetch_user_info(at)
    name = email.split("@")[0]
    uid = ""
    if info:
        name = info.get("name", info.get("displayName", name))
        uid = info.get("id", info.get("userId", ""))
        log(f"[{email}] User: {name} (ID: {uid})", "OK")

    exp = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    elapsed = time.time() - start_time

    out = {"success": True, "email": email, "displayName": name,
           "accessToken": at, "refreshToken": rt, "expiresAt": exp,
           "userId": uid, "elapsed": round(elapsed, 1)}

    if test_only:
        log(f"[{email}] [TEST] Token OK. Not saving. ({elapsed:.0f}s)", "OK")
        return out

    if save_to_9router_db(email, name, at, rt, exp, uid, mid):
        log(f"[{email}] Saved to 9router! ({elapsed:.0f}s)", "OK")
    else:
        log(f"[{email}] DB save failed", "ERR")
        out["success"] = False
        out["error"] = "db_save_failed"

    return out


# ══════════════════════════════════════════════════════════════════════
#  Batch processing with semaphore (concurrency control)
# ══════════════════════════════════════════════════════════════════════
async def run_batch(accounts, test_only=False, concurrent=1):
    sem = asyncio.Semaphore(concurrent)

    async def _run(email, password):
        async with sem:
            return await process_account(email, password, test_only=test_only)

    tasks = []
    for acc in accounts:
        email, pwd = acc.split(":", 1)
        tasks.append(_run(email, pwd))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Handle exceptions
    processed = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            email = accounts[i].split(":", 1)[0]
            processed.append({"success": False, "email": email, "error": str(r)})
        else:
            processed.append(r)

    return processed


# ══════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════
def parse_args():
    parser = argparse.ArgumentParser(
        description="Qoder Auto-Login for 9router",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python qoder_autologin.py user@gmail.com:password
  python qoder_autologin.py --batch accounts.txt
  python qoder_autologin.py --batch accounts.txt --headless --concurrent 3
  python qoder_autologin.py --test user@gmail.com:password
  python qoder_autologin.py --batch accounts.txt --test --headless

Account format (in file):
  email:password
  # lines starting with # are comments
  # blank lines are ignored
        """,
    )
    parser.add_argument("accounts", nargs="*",
                        help="email:password pairs (space-separated)")
    parser.add_argument("--batch", "-b", metavar="FILE",
                        help="Read accounts from file (one email:password per line)")
    parser.add_argument("--test", "-t", action="store_true",
                        help="Test mode: get token but don't save to DB")
    parser.add_argument("--headless", action="store_true",
                        help="Run browser in headless mode (invisible)")
    parser.add_argument("--concurrent", "-c", type=int, default=1,
                        help="Number of concurrent browser sessions (default: 1)")
    parser.add_argument("--debug", "-d", action="store_true",
                        help="Enable debug output")
    parser.add_argument("--min-version", default=MIN_9ROUTER_VERSION,
                        help=f"Minimum 9router version required (default: {MIN_9ROUTER_VERSION})")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Interactive mode: show info and ask before running")
    parser.add_argument("--no-skip-existing", action="store_true",
                        help="Re-login even if account already exists in 9router")
    parser.add_argument("--no-update", action="store_true",
                        help="Skip auto-update check")
    return parser.parse_args()


# ══════════════════════════════════════════════════════════════════════
#  Auto-update from Git
# ══════════════════════════════════════════════════════════════════════
REPO_URL = "https://github.com/andreanocalvin/qoder-autologin.git"

def check_for_updates():
    """Check for updates from the repo. Ask user before pulling."""
    import subprocess

    # Find script directory (where .git should be)
    script_dir = Path(__file__).parent.resolve()
    git_dir = script_dir / ".git"

    if not git_dir.exists():
        dbg("No .git directory found — skipping auto-update")
        return

    def _git(*args):
        try:
            r = subprocess.run(
                ["git"] + list(args),
                capture_output=True, text=True, timeout=15,
                cwd=str(script_dir),
            )
            return r.stdout.strip(), r.returncode
        except Exception as e:
            dbg(f"git {' '.join(args)} error: {e}")
            return "", 1

    # 1. Fetch latest from remote
    log("Checking for updates...", "WAIT")
    _, rc = _git("fetch", "origin", "main", "--quiet")
    if rc != 0:
        log("Could not reach remote repo — skipping update check", "ERR")
        return

    # 2. Check for new commits
    new_commits, rc = _git("log", "HEAD..origin/main", "--oneline")
    if rc != 0 or not new_commits:
        log("Already up to date! ✅", "OK")
        return

    # 3. Count and show new commits
    commit_lines = new_commits.strip().split("\n")
    num_commits = len(commit_lines)

    print()
    print("  ╔══════════════════════════════════════════════╗")
    print(f"  ║  🔄 Update available! ({num_commits} new commit{'s' if num_commits > 1 else ''})         ║")
    print("  ╠══════════════════════════════════════════════╣")
    for line in commit_lines[:5]:  # Show max 5 commits
        # Truncate long lines
        display = line[:44] if len(line) > 44 else line
        print(f"  ║  {display:<44}║")
    if num_commits > 5:
        print(f"  ║  ... and {num_commits - 5} more{' ' * 30}║")
    print("  ╚══════════════════════════════════════════════╝")
    print()

    # 4. Ask user
    try:
        answer = input("  Update now? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if answer == "n":
        log("Skipped update. Continuing with current version...", "INFO")
        return

    # 5. Pull
    log("Pulling latest changes...", "WAIT")
    output, rc = _git("pull", "origin", "main")
    if rc != 0:
        log(f"Git pull failed: {output}", "ERR")
        return

    # 6. Success — show what changed
    log(f"Updated! ({num_commits} commits pulled)", "OK")
    print()

    # 7. Re-exec the script with same arguments so new code takes effect
    log("Restarting with updated code...", "WAIT")
    python = sys.executable
    os.execv(python, [python] + sys.argv)


async def async_main():
    global HEADLESS, DEBUG_ENABLED

    args = parse_args()
    HEADLESS = args.headless
    DEBUG_ENABLED = args.debug

    # ── Auto-update check (before anything else) ──
    if not args.no_update:
        check_for_updates()

    # Override minimum version if specified
    min_ver = args.min_version

    # Collect accounts
    accounts = []

    if args.batch:
        try:
            with open(args.batch) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and ":" in line:
                        accounts.append(line)
        except FileNotFoundError:
            log(f"File not found: {args.batch}", "ERR")
            sys.exit(1)
        log(f"Loaded {len(accounts)} accounts from {args.batch}")

    if args.accounts:
        for acc in args.accounts:
            if ":" in acc:
                accounts.append(acc)
            else:
                log(f"Bad format (need email:password): {acc}", "ERR")

    if not accounts:
        log("No accounts provided. Use --batch FILE or pass email:password", "ERR")
        log("Run with --help for usage info.", "ERR")
        sys.exit(1)

    # ── Skip existing accounts ──
    if not args.test and not args.no_skip_existing:
        existing = get_existing_qoder_emails()
        if existing:
            before = len(accounts)
            accounts = [acc for acc in accounts if acc.split(":", 1)[0].lower() not in existing]
            skipped = before - len(accounts)
            if skipped:
                log(f"Skipped {skipped} account(s) already in 9router DB")
            if not accounts:
                log("All accounts already exist in 9router. Nothing to do.", "OK")
                sys.exit(0)

    # ── Interactive mode ──
    if args.interactive:
        print(f"  [i] Found {len(accounts)} account(s)")
        print()
        print("  ---------------------------------------------------")
        for i, acc in enumerate(accounts[:10]):
            email = acc.split(":", 1)[0]
            print(f"    {email}")
        if len(accounts) > 10:
            print(f"    ... dan {len(accounts)-10} akun lainnya")
        print("  ---------------------------------------------------")
        print()

        # Ask headless
        headless_input = input("  Headless mode? (browser invisible) [y/N]: ").strip().lower()
        HEADLESS = headless_input == "y"
        args.headless = HEADLESS
        print()

        # Ask concurrent
        conc_input = input("  Concurrent browsers (1-5) [1]: ").strip()
        try:
            conc = int(conc_input)
            conc = max(1, min(5, conc))
        except:
            conc = 1
        args.concurrent = conc
        print()

        # Summary
        mode_str = "Headless (invisible)" if HEADLESS else "Visible"
        print("  +--------------------------------------+")
        print(f"  |  Accounts:   {len(accounts)}")
        print(f"  |  Browser:    {mode_str}")
        print(f"  |  Concurrent: {args.concurrent}")
        print(f"  |  Save to:    9router DB")
        print("  +--------------------------------------+")
        print()

        # Confirm
        confirm = input("  Start login? [Y/n]: ").strip().lower()
        if confirm == "n":
            print()
            print("  Cancelled.")
            sys.exit(0)
        print()
        print("  Starting...")
        print()

    # Header
    mode = "HEADLESS" if HEADLESS else "VISIBLE"
    test = " | TEST MODE" if args.test else ""
    log(f"Qoder Auto-Login v3 | {len(accounts)} account(s) | {mode} | concurrent={args.concurrent}{test}")

    # ── 9router version check ──
    installed, version, version_ok = check_9router_version(min_ver)

    if not installed:
        log("9router is NOT installed!", "ERR")
        log("Install it first:  npm install -g 9router", "ERR")
        sys.exit(1)

    log(f"9router version: {version}")

    if not version_ok:
        log(f"9router version {version} is TOO OLD!", "ERR")
        log(f"Minimum required: {min_ver}", "ERR")
        log(f"Update with:  npm install -g 9router@latest", "ERR")
        log(f"Then restart 9router before running this tool.", "ERR")
        sys.exit(1)

    if not args.test and (not NINEROUTER_DB_PATH or not NINEROUTER_DB_PATH.exists()):
        log(f"9router database not found: {NINEROUTER_DB_PATH}", "ERR")
        log("Run 9router at least once to create the database.", "ERR")
        sys.exit(1)

    log(f"9router DB: {NINEROUTER_DB_PATH}")

    # Run
    start = time.time()
    results = await run_batch(accounts, test_only=args.test, concurrent=args.concurrent)

    # ── Retry loop for failed accounts ──
    max_retries = 3
    retry_count = 0

    while True:
        # Summary
        total_time = time.time() - start
        ok = sum(1 for r in results if r.get("success"))
        fail = len(results) - ok

        log(f"\n{'='*60}", "SUM")
        log(f"SUMMARY: {ok}✅ {fail}❌ | Total: {total_time:.1f}s | Avg: {total_time/max(len(results),1):.1f}s/account", "SUM")
        log(f"{'='*60}", "SUM")
        for r in results:
            s = "✅" if r.get("success") else "❌"
            e = _short_error(r.get("error", ""))
            t = f" ({r['elapsed']}s)" if r.get("elapsed") else ""
            n = f" → {r.get('displayName','')}" if r.get("displayName") and r.get("success") else ""
            log(f"  {s} {r['email']}{n}{t}{' — '+e if e else ''}", "SUM")

        if ok == len(results):
            log(f"\n🎉 All {ok} accounts processed successfully!", "OK")
            break

        # Failed accounts exist
        failed = [r for r in results if not r.get("success")]
        log(f"\n⚠️  {len(failed)} account(s) failed:", "ERR")
        for r in failed:
            log(f"  ❌ {r['email']} — {_short_error(r.get('error', 'unknown'))}", "ERR")

        # Ask to retry
        retry_count += 1
        if retry_count > max_retries:
            log(f"\nMax retries ({max_retries}) reached. Stopping.", "ERR")
            break

        try:
            print()
            answer = input(f"  Retry {len(failed)} failed account(s)? (attempt {retry_count}/{max_retries}) [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if answer != "y":
            log("Skipping retry.", "INFO")
            break

        # Collect failed accounts as "email:password" pairs
        # We need to look up passwords from the original accounts list
        failed_accounts = []
        failed_emails = {r["email"].lower() for r in failed}
        for acc in accounts:
            email = acc.split(":", 1)[0]
            if email.lower() in failed_emails:
                failed_accounts.append(acc)

        if not failed_accounts:
            log("No failed accounts to retry.", "ERR")
            break

        log(f"\n🔄 Retrying {len(failed_accounts)} account(s)...", "WAIT")
        results = await run_batch(failed_accounts, test_only=args.test, concurrent=args.concurrent)
        accounts = failed_accounts  # Update for potential next retry


def main():
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
