# app.py
# QueryVault - encrypted SQL notes with a modern-ish Qt UI
# - DB stored in %APPDATA%\QueryVault\secure_notes.db
# - Persian-friendly font loading (Vazirmatn)
#
# Install:
#   pip install pyside6 cryptography
#
# Run:
#   python app.py
#
# Build EXE (include font):
#   pyinstaller --noconsole --onefile --name QueryVault ^
#     --add-data "fonts/Vazirmatn-Regular.ttf;fonts" ^
#     app.py

import sys
import os
import base64
import sqlite3
from pathlib import Path
from datetime import datetime

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QLineEdit, QTextEdit, QPushButton,
    QLabel, QMessageBox, QSplitter, QFormLayout, QInputDialog
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase, QFont

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


# -----------------------------
# Storage in %APPDATA%
# -----------------------------
APP_NAME = "QueryVault"
APPDATA_DIR = Path(os.getenv("APPDATA") or ".") / APP_NAME
APPDATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(APPDATA_DIR / "secure_notes.db")


# -----------------------------
# Styling (dark, clean)
# -----------------------------
QSS = """
QMainWindow { background: #0f172a; }
QWidget {
  color: #e2e8f0;
  font-size: 13px;
}
QLineEdit, QTextEdit {
  background: #111827;
  border: 1px solid #243244;
  border-radius: 10px;
  padding: 10px;
  selection-background-color: #2563eb;
}
QListWidget {
  background: #0b1220;
  border: 1px solid #243244;
  border-radius: 12px;
  padding: 6px;
}
QPushButton {
  background: #1f2937;
  border: 1px solid #2b3a52;
  border-radius: 10px;
  padding: 10px 14px;
}
QPushButton:hover { background: #243244; }
QPushButton:pressed { background: #2b3a52; }
QLabel { color: #cbd5e1; }
"""


# -----------------------------
# Crypto helpers
# -----------------------------
def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt BLOB NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            tags TEXT,
            ciphertext BLOB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    # ensure salt exists
    cur.execute("SELECT salt FROM meta WHERE id=1")
    row = cur.fetchone()
    if row is None:
        cur.execute("INSERT INTO meta (id, salt) VALUES (1, ?)", (os.urandom(16),))
    con.commit()
    con.close()


def get_salt() -> bytes:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT salt FROM meta WHERE id=1")
    salt = cur.fetchone()[0]
    con.close()
    return salt


def derive_fernet_key(password: str, salt: bytes) -> bytes:
    # 32 bytes -> Fernet key (urlsafe base64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def encrypt_text(password: str, plaintext: str) -> bytes:
    f = Fernet(derive_fernet_key(password, get_salt()))
    return f.encrypt(plaintext.encode("utf-8"))


def decrypt_text(password: str, ciphertext: bytes) -> str:
    f = Fernet(derive_fernet_key(password, get_salt()))
    return f.decrypt(ciphertext).decode("utf-8")


# -----------------------------
# DB helpers
# -----------------------------
def list_notes_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, title, tags, updated_at FROM notes ORDER BY updated_at DESC")
    rows = cur.fetchall()
    con.close()
    return rows


def get_note_db(note_id: int):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, title, tags, ciphertext FROM notes WHERE id=?", (note_id,))
    row = cur.fetchone()
    con.close()
    return row


def create_note_db(title: str, tags: str, ciphertext: bytes):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    t = now_iso()
    cur.execute(
        "INSERT INTO notes (title, tags, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (title, tags, ciphertext, t, t),
    )
    con.commit()
    new_id = cur.lastrowid
    con.close()
    return new_id


def update_note_db(note_id: int, title: str, tags: str, ciphertext: bytes):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "UPDATE notes SET title=?, tags=?, ciphertext=?, updated_at=? WHERE id=?",
        (title, tags, ciphertext, now_iso(), note_id),
    )
    con.commit()
    con.close()


def delete_note_db(note_id: int):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("DELETE FROM notes WHERE id=?", (note_id,))
    con.commit()
    con.close()


# -----------------------------
# Utility: resource path (PyInstaller)
# -----------------------------
def resource_path(relative: str) -> str:
    """
    Get absolute path for bundled resources (PyInstaller) or local dev.
    """
    base = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base, relative)


# -----------------------------
# Main UI
# -----------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QueryVault")
        self.resize(1100, 700)

        self.password = None
        self.current_id = None

        # Ask for password
        self.password = self.prompt_password()
        if not self.password:
            sys.exit(0)

        # Root layout
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(10)

        # Top bar
        header = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("جستجو در عنوان/تگ‌ها… (Search title/tags)")
        self.btn_new = QPushButton("جدید (New)")
        self.btn_save = QPushButton("ذخیره (Save)")
        self.btn_delete = QPushButton("حذف (Delete)")
        self.btn_copy = QPushButton("کپی SQL (Copy)")
        header.addWidget(self.search, 1)
        header.addWidget(self.btn_new)
        header.addWidget(self.btn_save)
        header.addWidget(self.btn_delete)
        header.addWidget(self.btn_copy)
        outer.addLayout(header)

        # Splitter
        splitter = QSplitter(Qt.Horizontal)
        outer.addWidget(splitter, 1)

        # Left panel
        left = QWidget()
        left_l = QVBoxLayout(left)
        left_l.setContentsMargins(0, 0, 0, 0)
        left_l.setSpacing(8)
        left_l.addWidget(QLabel("کوئری‌ها (Queries)"))
        self.list = QListWidget()
        left_l.addWidget(self.list, 1)
        splitter.addWidget(left)

        # Right panel
        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.setContentsMargins(0, 0, 0, 0)
        right_l.setSpacing(10)

        form = QFormLayout()
        self.title = QLineEdit()
        self.tags = QLineEdit()
        self.title.setPlaceholderText("عنوان (Title)")
        self.tags.setPlaceholderText("تگ‌ها مثل: مهر, گزارش, debug  (comma separated)")
        form.addRow("عنوان", self.title)
        form.addRow("تگ‌ها", self.tags)
        right_l.addLayout(form)

        self.editor = QTextEdit()
        self.editor.setPlaceholderText("-- SQL را اینجا قرار بده\n-- paste your SQL here")
        right_l.addWidget(self.editor, 1)
        splitter.addWidget(right)
        splitter.setSizes([320, 780])

        # Direction preferences:
        # - Persian fields RTL
        # - SQL editor LTR
        self.title.setLayoutDirection(Qt.RightToLeft)
        self.tags.setLayoutDirection(Qt.RightToLeft)
        self.editor.setLayoutDirection(Qt.LeftToRight)

        # Signals
        self.search.textChanged.connect(self.refresh_list)
        self.list.itemClicked.connect(self.on_select)
        self.btn_new.clicked.connect(self.new_note)
        self.btn_save.clicked.connect(self.save_note)
        self.btn_delete.clicked.connect(self.delete_note)
        self.btn_copy.clicked.connect(self.copy_sql)

        self.refresh_list()

    def prompt_password(self):
        pw, ok = QInputDialog.getText(self, "Unlock", "Password:", QLineEdit.Password)
        return pw if ok and pw else None

    def refresh_list(self):
        q = (self.search.text() or "").strip().lower()
        self.list.clear()

        for nid, title, tags, updated in list_notes_db():
            hay = f"{title} {tags or ''}".lower()
            if q and q not in hay:
                continue

            subtitle = (tags or "").strip()
            text = f"{title}\n{subtitle}" if subtitle else title

            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, nid)
            self.list.addItem(item)

    def on_select(self, item: QListWidgetItem):
        nid = item.data(Qt.UserRole)
        row = get_note_db(nid)
        if not row:
            return

        _id, title, tags, ciphertext = row
        try:
            body = decrypt_text(self.password, ciphertext)
        except Exception:
            QMessageBox.critical(self, "Error", "Password اشتباه است یا داده خراب شده.")
            return

        self.current_id = _id
        self.title.setText(title)
        self.tags.setText(tags or "")
        self.editor.setPlainText(body)

    def new_note(self):
        self.current_id = None
        self.title.setText("")
        self.tags.setText("")
        self.editor.setPlainText("")

    def save_note(self):
        title = self.title.text().strip() or "بدون عنوان"
        tags = self.tags.text().strip()
        body = self.editor.toPlainText()

        try:
            ct = encrypt_text(self.password, body)
        except Exception as e:
            QMessageBox.critical(self, "Encrypt Error", str(e))
            return

        if self.current_id is None:
            self.current_id = create_note_db(title, tags, ct)
        else:
            update_note_db(self.current_id, title, tags, ct)

        self.refresh_list()

    def delete_note(self):
        if self.current_id is None:
            return
        delete_note_db(self.current_id)
        self.new_note()
        self.refresh_list()

    def copy_sql(self):
        QApplication.clipboard().setText(self.editor.toPlainText())
        QMessageBox.information(self, "Copied", "SQL کپی شد ✅")


def apply_persian_font(app: QApplication):
    """
    Loads Vazirmatn font if present; otherwise fall back to system font.
    Put font at: fonts/Vazirmatn-Regular.ttf
    """
    font_path = resource_path(os.path.join("fonts", "Vazirmatn-Regular.ttf"))
    if os.path.exists(font_path):
        font_id = QFontDatabase.addApplicationFont(font_path)
        if font_id != -1:
            family = QFontDatabase.applicationFontFamilies(font_id)[0]
            app.setFont(QFont(family, 11))


if __name__ == "__main__":
    init_db()

    app = QApplication(sys.argv)
    apply_persian_font(app)
    app.setStyleSheet(QSS)

    w = MainWindow()
    w.show()

    sys.exit(app.exec())
