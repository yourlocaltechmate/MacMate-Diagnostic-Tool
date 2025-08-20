# MacMate Diagnostic Tool

A full-featured Mac diagnostics tool built in Python with Flet. Monitors CPU, RAM, storage, battery, network, installed apps, top processes, and more. Supports encrypted email reporting securely.

---

## Features

* CPU per-core usage and temperature monitoring
* RAM usage details
* Storage usage and SMART status
* Battery status and cycle count
* Network upload/download monitoring
* Installed apps and top running processes
* Encrypted email reporting
* Dark-mode Flet GUI

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/yourlocaltechmate/MacMate-Diagnostic-Tool.git
cd MacMate-Diagnostic-Tool
```

### 2. Create your `.env` file

The `.env` file stores your secret key for encrypting/decrypting sensitive data. **Never commit your real `.env` file to GitHub**. Use `.env.example` as a template:

```bash
cp .env.example .env
```

Generate a secure secret key and write it into `.env`:

```bash
python3 -c "from cryptography.fernet import Fernet; print('SECRET_KEY=' + Fernet.generate_key().decode())" > .env
```

Verify the `.env` file:

```bash
cat .env
```

You should see something like:

```
SECRET_KEY=some-random-base64-key==
```

---

### 3. Install dependencies

If `requirements.txt` exists:

```bash
python3 -m pip install -r requirements.txt
```

Otherwise, install manually:

```bash
python3 -m pip install flet psutil cryptography python-dotenv certifi
```

---

### 4. Configure email for reporting (optional)

To use the email reporting feature safely:

1. Create your own Gmail or SMTP account.
2. Encrypt your email and password using the secret key in `.env`:

```python
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
fernet = Fernet(SECRET_KEY.encode())

email = "youremail@example.com"
password = "yourpassword"

encrypted_email = fernet.encrypt(email.encode())
encrypted_password = fernet.encrypt(password.encode())

print("ENCRYPTED_EMAIL =", encrypted_email)
print("ENCRYPTED_PASSWORD =", encrypted_password)
```

3. Replace the placeholders in the script:

```python
ENCRYPTED_EMAIL = b"<your_encrypted_email_here>"
ENCRYPTED_PASSWORD = b"<your_encrypted_password_here>"
```

> Without this the email section will not work !

---

### 5. Run the tool

```bash
python3 Macmate_diagnostic_pbeta01.py
```

---

## Notes
* Email reporting requires the correct `SECRET_KEY` that matches your encrypted credentials. Without it, the script will run diagnostics but **email reporting will fail**.
* Optional utilities: `istats` (for CPU temperature, install with `sudo gem install iStats`), `diskutil` (for SMART info, macOS only).

---

## License

© Your Local Tech Mate – This tool is authored by Your Local Tech Mate and must not be sold or redistributed without explicit permission. Free to use and modify for personal or educational purposes only.






