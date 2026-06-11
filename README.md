# Qoder Auto-Login for 9router

Tool otomatis untuk login dan menambahkan akun Qoder ke 9router via Google SSO.
Reverse-engineered dari 9router v0.4.71.

## ✨ Features

- **Google SSO** auto-login (multi-language: EN, ID, dll)
- **Batch mode** — login banyak akun sekaligus dari file
- **Concurrent processing** — beberapa browser jalan bareng (1-5)
- **Headless mode** — browser invisible untuk automation
- **Auto-update** — cek update otomatis dari repo, tanya sebelum pull
- **Retry failed** — akun yang gagal bisa langsung di-retry (max 3x)
- **Skip existing** — auto-skip akun yang sudah ada di 9router DB
- **Consent handler** — otomatis handle semua Google agreement screens:
  - "Saya mengerti" / "I understand"
  - "Continue" / "Lanjutkan"
  - "This app isn't verified" → Advanced → Go to...
  - OAuth scope consent
  - Workspace admin consent
- **Interactive mode** — preview akun + toggle headless + confirm sebelum jalan
- **9router version check** — block kalau versi 9router terlalu lama
- **PKCE + nonce** — secure device auth flow (sama persis kayak 9router)

## 📋 Requirements

| Requirement | Minimum |
|-------------|---------|
| **Windows** | 10 / 11 |
| **Python** | 3.10+ |
| **9router** | v0.4.71+ (auto-checked) |
| **Node.js** | Required by 9router |

## 🚀 Quick Start

### 1. Install

```bash
# Clone repo
git clone https://github.com/andreanocalvin/qoder-autologin.git
cd qoder-autologin

# Auto-install dependencies
setup.bat
```

Atau manual:
```bash
pip install -r requirements.txt
playwright install chromium
```

### 2. Pakai

**Single account:**
```bash
qoder-login.bat email@gmail.com:password123
```

**Batch dari file:**
```bash
qoder-login.bat --batch accounts.txt
```

**Interactive (double-click `run-batch.bat`):**

```
  ===================================================
     Qoder Auto-Login for 9router - Batch Mode
  ===================================================

  [i] Found 14 account(s) in accounts.txt

  ---------------------------------------------------
    email1@gmail.com
    email2@gmail.com
    ...
  ---------------------------------------------------

  Headless mode? (browser invisible) [y/N]: n
  Concurrent browsers (1-5) [1]: 2

  +--------------------------------------+
  |  Accounts:   14
  |  Browser:    Visible
  |  Concurrent: 2
  |  Save to:    9router DB
  +--------------------------------------+

  Start login? [Y/n]:
```

## 📁 File Structure

```
qoder-autologin/
├── qoder_autologin.py      ← Script utama
├── setup.bat               ← Auto-installer (Python + Playwright)
├── qoder-login.bat         ← CLI launcher
├── run-batch.bat           ← Interactive batch launcher
├── accounts.txt            ← Akun kamu (jangan di-commit!)
├── accounts.txt.example    ← Template (safe to commit)
├── requirements.txt        ← Python dependencies
├── .gitignore
└── README.md
```

## 📝 Format accounts.txt

```
# Komentar diawali # (di-skip)
# Baris kosong juga di-skip

email1@gmail.com:password1
email2@gmail.com:password2
email3@workspace.com:password3
```

## 🔧 CLI Options

```
usage: qoder_autologin.py [-h] [--batch FILE] [--headless]
                          [--concurrent N] [--test] [--debug]
                          [--min-version VER] [--interactive]
                          [--no-skip-existing] [--no-update]
                          [accounts ...]

positional arguments:
  accounts              email:password pairs

options:
  -b, --batch FILE      Read accounts from file
  --headless            Run browser in headless mode
  -c, --concurrent N    Concurrent browser sessions (1-5, default: 1)
  -t, --test            Test mode (don't save to DB)
  -d, --debug           Debug output
  --min-version VER     Minimum 9router version (default: 0.4.71)
  -i, --interactive     Interactive prompts before running
  --no-skip-existing    Re-login even if account exists in 9router
  --no-update           Skip auto-update check
```

## 🔄 Auto-Update

Setiap kali script dijalankan, otomatis cek update dari repo:

```
[13:10:27] ⏳ Checking for updates...

  ╔══════════════════════════════════════════════╗
  ║  🔄 Update available! (2 new commits)         ║
  ╠══════════════════════════════════════════════╣
  ║  3b1a951 feat: auto-update check              ║
  ║  6608d26 perf: optimize login speed           ║
  ╚══════════════════════════════════════════════╝

  Update now? [Y/n]: y
```

- Jawab **Y** → pull + restart otomatis dengan code baru
- Jawab **n** → skip, lanjut pakai versi sekarang
- Pakai `--no-update` untuk skip cek sama sekali

## 🔁 Retry Failed Accounts

Kalau ada akun yang gagal di akhir batch, script tanya mau retry:

```
📊 SUMMARY: 6✅ 2❌ | Total: 192.0s | Avg: 24.0s/account
============================================================
  ✅ email1@gmail.com → JohnDoe (24s)
  ✅ email2@gmail.com → JaneSmith (25s)
  ...
  ❌ email7@gmail.com — Timeout 30000ms exceeded.
  ❌ email8@gmail.com — navigation interrupted

⚠️  2 account(s) failed:
  ❌ email7@gmail.com — Timeout 30000ms exceeded.
  ❌ email8@gmail.com — navigation interrupted

  Retry 2 failed account(s)? (attempt 1/3) [y/N]: y

🔄 Retrying 2 account(s)...
```

- Max **3 retry attempts** per batch
- Hanya ulang akun yang gagal (bukan semua)
- Jawab **n** atau Enter untuk skip

## 🛡️ Safety Features

### Skip Existing Accounts
By default, akun yang sudah ada di 9router DB **di-skip otomatis**.
Gunakan `--no-skip-existing` untuk force re-login (misal token expired).

### 9router Version Check
Script akan **block** kalau 9router versi terlalu lama:
```
[ERR] 9router version 0.4.55 is TOO OLD!
[ERR] Minimum required: 0.4.71
[ERR] Update with:  npm install -g 9router@latest
```

### Test Mode
`--test` flag: jalankan login tanpa save ke DB. Berguna untuk testing akun baru.

## ⚡ Performance

| Mode | Per Account | 10 Accounts | 50 Accounts |
|------|------------|-------------|-------------|
| Visible, concurrent=1 | ~24s | ~4 min | ~20 min |
| Headless, concurrent=1 | ~22s | ~3.5 min | ~18 min |
| Visible, concurrent=3 | ~24s each | ~1.5 min | ~7 min |
| Headless, concurrent=3 | ~22s each | ~1.2 min | ~6 min |

> ⚠️ Concurrent > 2 bisa trigger Google rate-limiting. Recommended: **concurrent 1-2**.

## 🐛 Troubleshooting

**Browser error / context destroyed:**
- Sudah di-handle otomatis (retry). Kalau masih gagal, coba `--concurrent 1`

**Token tidak datang:**
- Pastikan 9router versi >= 0.4.71
- Pastikan 9router sedang jalan
- Cek koneksi internet

**Google CAPTCHA / 2FA:**
- Browser visible (default) biar bisa handle manual
- Atau disable 2FA sementara di akun Google

**Consent screen stuck:**
- Script auto-handle kebanyakan consent screen
- Kalau ada yang baru, submit issue dengan screenshot

**Loading lambat di Playwright:**
- Normal — Playwright lebih lambat 2-5 detik dari Chrome biasa
- Kalau stuck banget, kemungkinan internet atau Google SSO server lagi down

## 📄 License

MIT — pakai sesuka hati.

## ⚠️ Disclaimer

Tool ini untuk penggunaan personal. Gunakan responsibly.
Penulis tidak bertanggung jawab atas penyalahgunaan tool ini.
