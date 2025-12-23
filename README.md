# QueryVault 🔐

A secure, offline-first desktop application for storing encrypted SQL queries and notes.

Built with **Python + PySide6**, inspired by **Standard Notes**.

---

## ✨ Features
- 🔐 Password-based encryption (AES / Fernet)
- 🗄 Local encrypted SQLite storage
- 🖥 Modern Qt UI (dark mode)
- 🇮🇷 Full Persian (RTL) support
- 🔍 Search by title and tags
- 📋 Copy SQL to clipboard
- 💾 Auto-save encrypted notes
- 🪟 Windows executable support

---

## 🧰 Tech Stack
- Python 3.11
- PySide6 (Qt)
- SQLite
- cryptography (PBKDF2 + Fernet)

---

## 🚀 Run locally

```bash
pip install -r requirements.txt
python app.py
