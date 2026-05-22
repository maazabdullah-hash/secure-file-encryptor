# Secure File Encryptor

Desktop tool to encrypt and decrypt files with AES-256-GCM and password-based key derivation (PBKDF2).

## Features

- **AES-256-GCM** authenticated encryption with random salt and nonce per file
- **PBKDF2-HMAC-SHA256** key derivation (100,000 iterations, 32-byte key)
- **Portable file format**: `[16-byte salt][12-byte nonce][ciphertext][16-byte tag]`
- **Tkinter GUI**: file picker, password field, encrypt/decrypt actions, status feedback
- **Clear error handling** for wrong password, corrupted files, and missing paths
- **pytest suite** covering round-trip, wrong password, and tamper detection

## Requirements

- Python 3.10 or newer
- Tkinter (included with most official Python installers on Windows/macOS/Linux)

## Setup

```bash
cd secure-file-encryptor
python -m venv .venv
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS / Linux:**

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## How to run

**GUI application:**

```bash
python src/main.py
```

1. Click **Browse…** and select a file.
2. Enter a strong password.
3. Click **Encrypt** or **Decrypt** and choose where to save the output.

**Run tests:**

```bash
pytest
```

## Project layout

```
secure-file-encryptor/
├── src/
│   ├── __init__.py
│   ├── main.py          # Application entry point
│   ├── gui.py           # Tkinter UI (no crypto logic)
│   ├── crypto.py        # Encrypt / decrypt file operations
│   └── key_manager.py   # PBKDF2 key derivation
├── tests/
│   └── test_crypto.py
├── screenshots/
├── requirements.txt
└── README.md
```

## Security notes

- Use a long, unique password; the tool does not store passwords.
- Keep backups of originals before encrypting; overwriting is your choice at save time.
- Encrypted files are only as strong as your password and the integrity of the file on disk.
## Screenshots

## Screenshots

### Main Window
![Main GUI](screenshots/main.png)

### Encrypt Tab
![Encrypt Screen](screenshots/encrypt.png)

### Decrypt Tab
![Decrypt Screen](screenshots/decrypt.png)

Use and modify for personal or educational purposes. Review cryptographic choices before production deployment.
