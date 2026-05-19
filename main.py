import base64
import hashlib
import hmac
import os
import random
import re
import secrets
import smtplib
import sqlite3
import uuid
import zipfile
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "random_coffee.db"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

app = FastAPI(title="Mriya Random Coffee")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class UserCreate(BaseModel):
    full_name: str = Field(min_length=1)
    email: EmailStr
    password: str = Field(min_length=4)
    department: str = Field(min_length=1)
    city: str = Field(min_length=1)
    interests: str = Field(min_length=1)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=10)
    new_password: str = Field(min_length=4)


class FeedbackRequest(BaseModel):
    text: str = Field(min_length=1)


class PhotoUploadRequest(BaseModel):
    data_url: str = Field(min_length=10)


class UserUpdate(BaseModel):
    full_name: str = Field(min_length=1)
    email: EmailStr
    department: str = Field(min_length=1)
    city: str = Field(min_length=1)
    interests: str = Field(min_length=1)


class User(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    department: str
    city: str
    interests: str
    photo_url: Optional[str] = None
    created_at: str


class Pair(BaseModel):
    id: int
    user1: User
    user2: User
    created_at: str
    meeting_start: Optional[str] = None
    meeting_end: Optional[str] = None
    meeting_time: Optional[str] = None


class AuthResponse(BaseModel):
    token: str
    user: User


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def default_meeting_times() -> tuple[str, str]:
    start = datetime.now() + timedelta(days=1)
    start = start.replace(hour=12, minute=0, second=0, microsecond=0)
    end = start + timedelta(minutes=30)

    return (
        start.isoformat(timespec="seconds"),
        end.isoformat(timespec="seconds"),
    )


def format_meeting_time(start_iso: Optional[str], end_iso: Optional[str]) -> str:
    if not start_iso or not end_iso:
        return "Время встречи не назначено"

    start = datetime.fromisoformat(start_iso)
    end = datetime.fromisoformat(end_iso)

    return f"{start.strftime('%d.%m.%Y %H:%M')}–{end.strftime('%H:%M')}"


def normalize_email(value: str) -> str:
    return str(value or "").strip().lower()


def require_admin(x_admin_password: Optional[str]):
    if x_admin_password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Неверный пароль администратора")


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    ).hex()

    return salt, password_hash


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, actual_hash = hash_password(password, salt)
    return hmac.compare_digest(actual_hash, expected_hash)


def row_to_user_simple(row) -> dict:
    return {
        "id": row["id"],
        "full_name": row["full_name"],
        "email": row["email"],
        "department": row["department"],
        "city": row["city"],
        "interests": row["interests"],
        "photo_url": row["photo_url"] if "photo_url" in row.keys() else None,
        "created_at": row["created_at"],
    }


def row_to_user(row, prefix):
    return {
        "id": row[f"{prefix}_id"],
        "full_name": row[f"{prefix}_full_name"],
        "email": row[f"{prefix}_email"],
        "department": row[f"{prefix}_department"],
        "city": row[f"{prefix}_city"],
        "interests": row[f"{prefix}_interests"],
        "photo_url": row[f"{prefix}_photo_url"] if f"{prefix}_photo_url" in row.keys() else None,
        "created_at": row[f"{prefix}_created_at"],
    }


def get_user_by_token(x_user_token: Optional[str]) -> sqlite3.Row:
    if not x_user_token:
        raise HTTPException(status_code=401, detail="Не выполнен вход")

    with get_db() as db:
        session = db.execute("""
            SELECT user_id
            FROM sessions
            WHERE token = ?
        """, (x_user_token,)).fetchone()

        if not session:
            raise HTTPException(status_code=401, detail="Сессия не найдена")

        user = db.execute("""
            SELECT id, full_name, email, department, city, interests, photo_url, created_at
            FROM users
            WHERE id = ?
        """, (session["user_id"],)).fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Пользователь не найден")

        return user


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                department TEXT NOT NULL,
                city TEXT NOT NULL,
                interests TEXT NOT NULL,
                password_salt TEXT,
                password_hash TEXT,
                created_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user1_id INTEGER NOT NULL,
                user2_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                meeting_start TEXT,
                meeting_end TEXT,
                FOREIGN KEY(user1_id) REFERENCES users(id),
                FOREIGN KEY(user2_id) REFERENCES users(id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS feedbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                full_name TEXT,
                email TEXT,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        cursor = db.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]

        if "password_salt" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN password_salt TEXT")

        if "password_hash" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")

        cursor = db.execute("PRAGMA table_info(pairs)")
        pair_columns = [row[1] for row in cursor.fetchall()]

        if "meeting_start" not in pair_columns:
            db.execute("ALTER TABLE pairs ADD COLUMN meeting_start TEXT")

        if "meeting_end" not in pair_columns:
            db.execute("ALTER TABLE pairs ADD COLUMN meeting_end TEXT")

        if "photo_url" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN photo_url TEXT")

        db.commit()


@app.on_event("startup")
def startup():
    init_db()



def _excel_col_name(index: int) -> str:
    name = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(65 + remainder) + name
    return name


def _xlsx_sheet_xml(headers: list[str], rows: list[list[object]]) -> str:
    all_rows = [headers] + rows
    xml_rows = []

    for row_index, row in enumerate(all_rows, start=1):
        cells = []

        for col_index, value in enumerate(row):
            cell_ref = f"{_excel_col_name(col_index)}{row_index}"
            safe_value = xml_escape("" if value is None else str(value))
            cells.append(
                f'<c r="{cell_ref}" t="inlineStr"><is><t>{safe_value}</t></is></c>'
            )

        xml_rows.append(f'<row r="{row_index}">{"".join(cells)}</row>')

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData>'
        + ''.join(xml_rows) +
        '</sheetData>'
        '</worksheet>'
    )


def build_xlsx(headers: list[str], rows: list[list[object]]) -> bytes:
    output = BytesIO()

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '</Types>'
        )

        archive.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
            '</Relationships>'
        )

        archive.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Export" sheetId="1" r:id="rId1"/></sheets>'
            '</workbook>'
        )

        archive.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
            '</Relationships>'
        )

        archive.writestr("xl/worksheets/sheet1.xml", _xlsx_sheet_xml(headers, rows))

    return output.getvalue()


def xlsx_response(filename: str, content: bytes) -> Response:
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/")
def index():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.post("/api/users")
def register_user(user: UserCreate):
    email = normalize_email(str(user.email))
    salt, password_hash = hash_password(user.password)

    with get_db() as db:
        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="Пользователь с такой почтой уже зарегистрирован"
            )

        db.execute("""
            INSERT INTO users (
                full_name,
                email,
                department,
                city,
                interests,
                password_salt,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user.full_name.strip(),
            email,
            user.department.strip(),
            user.city.strip(),
            user.interests.strip(),
            salt,
            password_hash,
            now_iso(),
        ))

        db.commit()

    return {"ok": True, "message": "Анкета успешно заполнена"}


@app.post("/api/auth/login", response_model=AuthResponse)
def login(payload: LoginRequest):
    email = normalize_email(str(payload.email))

    with get_db() as db:
        user = db.execute("""
            SELECT id, full_name, email, department, city, interests, photo_url, created_at, password_salt, password_hash
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        if not user or not user["password_salt"] or not user["password_hash"]:
            raise HTTPException(status_code=401, detail="Неверный email или пароль")

        if not verify_password(payload.password, user["password_salt"], user["password_hash"]):
            raise HTTPException(status_code=401, detail="Неверный email или пароль")

        token = secrets.token_urlsafe(32)

        db.execute("""
            INSERT INTO sessions (token, user_id, created_at)
            VALUES (?, ?, ?)
        """, (token, user["id"], now_iso()))
        db.commit()

        return {
            "token": token,
            "user": row_to_user_simple(user),
        }


@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordRequest):
    email = normalize_email(str(payload.email))

    with get_db() as db:
        user = db.execute("""
            SELECT id, full_name, email
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            expires_at = (datetime.now() + timedelta(hours=2)).isoformat(timespec="seconds")

            db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user["id"],))
            db.execute("""
                INSERT INTO password_reset_tokens (
                    token,
                    user_id,
                    expires_at,
                    used_at,
                    created_at
                )
                VALUES (?, ?, ?, NULL, ?)
            """, (token, user["id"], expires_at, now_iso()))
            db.commit()

            reset_link = f"{BASE_URL}/#reset-password?token={token}"
            body = f"""
Привет, {user['full_name']}!

Ты запросил смену пароля для Random Coffee.

Перейди по ссылке и задай новый пароль:
{reset_link}

Ссылка действительна 2 часа.

Если ты не запрашивал смену пароля, просто проигнорируй это письмо.
""".strip()

            send_email_safe(user["email"], "Random Coffee — смена пароля", body)

    return {
        "ok": True,
        "message": "Если пользователь с такой почтой зарегистрирован, письмо для смены пароля отправлено."
    }


@app.post("/api/auth/reset-password")
def reset_password(payload: ResetPasswordRequest):
    now = datetime.now()

    with get_db() as db:
        reset = db.execute("""
            SELECT token, user_id, expires_at, used_at
            FROM password_reset_tokens
            WHERE token = ?
        """, (payload.token,)).fetchone()

        if not reset:
            raise HTTPException(status_code=400, detail="Ссылка для смены пароля недействительна")

        if reset["used_at"]:
            raise HTTPException(status_code=400, detail="Ссылка уже была использована")

        expires_at = datetime.fromisoformat(reset["expires_at"])
        if expires_at < now:
            raise HTTPException(status_code=400, detail="Срок действия ссылки истёк")

        salt, password_hash = hash_password(payload.new_password)

        db.execute("""
            UPDATE users
            SET password_salt = ?, password_hash = ?
            WHERE id = ?
        """, (salt, password_hash, reset["user_id"]))

        db.execute("""
            UPDATE password_reset_tokens
            SET used_at = ?
            WHERE token = ?
        """, (now_iso(), payload.token))

        db.execute("DELETE FROM sessions WHERE user_id = ?", (reset["user_id"],))
        db.commit()

    return {"ok": True, "message": "Пароль успешно изменён"}


@app.get("/api/me", response_model=User)
def get_me(x_user_token: Optional[str] = Header(default=None)):
    user = get_user_by_token(x_user_token)
    return row_to_user_simple(user)


@app.put("/api/me", response_model=User)
def update_me(request: UserUpdate, x_user_token: Optional[str] = Header(default=None)):
    user = get_user_by_token(x_user_token)
    email = normalize_email(str(request.email))

    with get_db() as db:
        duplicate = db.execute("""
            SELECT id
            FROM users
            WHERE email = ? AND id <> ?
        """, (email, user["id"])).fetchone()

        if duplicate:
            raise HTTPException(status_code=400, detail="Пользователь с такой почтой уже зарегистрирован")

        db.execute("""
            UPDATE users
            SET full_name = ?,
                email = ?,
                department = ?,
                city = ?,
                interests = ?
            WHERE id = ?
        """, (
            request.full_name.strip(),
            email,
            request.department.strip(),
            request.city.strip(),
            request.interests.strip(),
            user["id"],
        ))
        db.commit()

        updated = db.execute("""
            SELECT id, full_name, email, department, city, interests, photo_url, created_at
            FROM users
            WHERE id = ?
        """, (user["id"],)).fetchone()

    return row_to_user_simple(updated)



@app.post("/api/me/photo")
def upload_my_photo(request: PhotoUploadRequest, x_user_token: Optional[str] = Header(default=None)):
    user = get_user_by_token(x_user_token)
    data_url = request.data_url.strip()

    match = re.match(r"^data:image/(png|jpeg|jpg|webp|gif);base64,(.+)$", data_url, re.IGNORECASE)

    if not match:
        raise HTTPException(status_code=400, detail="Некорректный формат изображения")

    image_type = match.group(1).lower()
    encoded = match.group(2)

    if image_type == "jpeg":
        image_type = "jpg"

    try:
        content = base64.b64decode(encoded, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Не удалось прочитать изображение")

    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Размер фото не должен превышать 5 МБ")

    uploads_dir = BASE_DIR / "static" / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)

    filename = f"user_{user['id']}.{image_type}"
    target = uploads_dir / filename

    with open(target, "wb") as f:
        f.write(content)

    photo_url = f"/static/uploads/{filename}"

    with get_db() as db:
        db.execute("UPDATE users SET photo_url = ? WHERE id = ?", (photo_url, user["id"]))
        db.commit()

    return {"photo_url": photo_url}


@app.get("/api/me/pair")
def get_my_pair(x_user_token: Optional[str] = Header(default=None)):
    user = get_user_by_token(x_user_token)

    with get_db() as db:
        row = db.execute("""
            SELECT
                p.id,
                p.created_at,
                p.meeting_start,
                p.meeting_end,

                u1.id AS u1_id,
                u1.full_name AS u1_full_name,
                u1.email AS u1_email,
                u1.department AS u1_department,
                u1.city AS u1_city,
                u1.interests AS u1_interests,
                u1.photo_url AS u1_photo_url,
                u1.created_at AS u1_created_at,

                u2.id AS u2_id,
                u2.full_name AS u2_full_name,
                u2.email AS u2_email,
                u2.department AS u2_department,
                u2.city AS u2_city,
                u2.interests AS u2_interests,
                u2.photo_url AS u2_photo_url,
                u2.created_at AS u2_created_at
            FROM pairs p
            JOIN users u1 ON u1.id = p.user1_id
            JOIN users u2 ON u2.id = p.user2_id
            WHERE p.user1_id = ? OR p.user2_id = ?
            ORDER BY p.created_at DESC
            LIMIT 1
        """, (user["id"], user["id"])).fetchone()

    if not row:
        return {"has_pair": False, "pair": None, "partner": None}

    meeting_start = row["meeting_start"]
    meeting_end = row["meeting_end"]

    if not meeting_start or not meeting_end:
        meeting_start, meeting_end = default_meeting_times()

    pair = {
        "id": row["id"],
        "created_at": row["created_at"],
        "meeting_start": meeting_start,
        "meeting_end": meeting_end,
        "meeting_time": format_meeting_time(meeting_start, meeting_end),
        "user1": row_to_user(row, "u1"),
        "user2": row_to_user(row, "u2"),
    }

    partner = pair["user2"] if pair["user1"]["id"] == user["id"] else pair["user1"]

    return {
        "has_pair": True,
        "pair": pair,
        "partner": partner,
    }


@app.delete("/api/me")
def leave_me(x_user_token: Optional[str] = Header(default=None)):
    user = get_user_by_token(x_user_token)
    leave_user_by_id(user["id"])
    return {"ok": True, "message": "Участник удалён"}


def leave_user_by_id(user_id: int):
    with get_db() as db:
        pairs = db.execute("""
            SELECT user1_id, user2_id
            FROM pairs
            WHERE user1_id = ? OR user2_id = ?
        """, (user_id, user_id)).fetchall()

        for pair in pairs:
            partner_id = pair["user2_id"] if pair["user1_id"] == user_id else pair["user1_id"]
            partner = db.execute("SELECT email, full_name FROM users WHERE id = ?", (partner_id,)).fetchone()

            if partner:
                send_email_safe(
                    partner["email"],
                    "Random Coffee — участник вышел",
                    "⚠️ Твой Random Coffee собеседник вышел из участия. Текущая пара сброшена."
                )

        db.execute("DELETE FROM pairs WHERE user1_id = ? OR user2_id = ?", (user_id, user_id))
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()


@app.delete("/api/users/by-email/{email}")
def leave_user(email: str, x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)
    email = normalize_email(email)

    with get_db() as db:
        user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="Участник не найден")

    leave_user_by_id(user["id"])

    return {"ok": True, "message": "Участник удалён"}



@app.post("/api/feedback")
def create_feedback(request: FeedbackRequest, x_user_token: Optional[str] = Header(default=None)):
    user = get_user_by_token(x_user_token)
    text = request.text.strip()

    if not text:
        raise HTTPException(status_code=400, detail="Введите текст отзыва")

    with get_db() as db:
        db.execute("""
            INSERT INTO feedbacks (
                user_id,
                full_name,
                email,
                text,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            user["id"],
            user["full_name"],
            user["email"],
            text,
            now_iso()
        ))
        db.commit()

    return {"ok": True}


@app.get("/api/feedbacks")
def get_feedbacks(x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        rows = db.execute("""
            SELECT id, full_name, email, text, created_at
            FROM feedbacks
            ORDER BY created_at DESC
        """).fetchall()

    return [
        {
            "id": row["id"],
            "full_name": row["full_name"],
            "email": row["email"],
            "text": row["text"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]


@app.get("/api/export/feedbacks.xlsx")
def export_feedbacks_excel(x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        rows = db.execute("""
            SELECT full_name, email, text, created_at
            FROM feedbacks
            ORDER BY created_at DESC
        """).fetchall()

    headers = ["Имя", "Email", "Отзыв", "Дата"]
    data = [
        [
            row["full_name"],
            row["email"],
            row["text"],
            row["created_at"],
        ]
        for row in rows
    ]

    return xlsx_response("random-coffee-feedbacks.xlsx", build_xlsx(headers, data))


@app.get("/api/users", response_model=List[User])
def get_users(x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        rows = db.execute("""
            SELECT id, full_name, email, department, city, interests, photo_url, created_at
            FROM users
            ORDER BY full_name
        """).fetchall()

    return [dict(row) for row in rows]


@app.get("/api/pairs", response_model=List[Pair])
def get_pairs(x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        rows = db.execute("""
            SELECT
                p.id,
                p.created_at,
                p.meeting_start,
                p.meeting_end,

                u1.id AS u1_id,
                u1.full_name AS u1_full_name,
                u1.email AS u1_email,
                u1.department AS u1_department,
                u1.city AS u1_city,
                u1.interests AS u1_interests,
                u1.photo_url AS u1_photo_url,
                u1.created_at AS u1_created_at,

                u2.id AS u2_id,
                u2.full_name AS u2_full_name,
                u2.email AS u2_email,
                u2.department AS u2_department,
                u2.city AS u2_city,
                u2.interests AS u2_interests,
                u2.photo_url AS u2_photo_url,
                u2.created_at AS u2_created_at
            FROM pairs p
            JOIN users u1 ON u1.id = p.user1_id
            JOIN users u2 ON u2.id = p.user2_id
            ORDER BY p.created_at DESC
        """).fetchall()

    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "created_at": row["created_at"],
            "meeting_start": row["meeting_start"],
            "meeting_end": row["meeting_end"],
            "meeting_time": format_meeting_time(row["meeting_start"], row["meeting_end"]),
            "user1": row_to_user(row, "u1"),
            "user2": row_to_user(row, "u2")
        })

    return result


@app.post("/api/pairs/create")
def create_pairs(x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        users = db.execute("""
            SELECT id, full_name, email, department, city, interests, photo_url, created_at
            FROM users
        """).fetchall()

        if len(users) < 2:
            raise HTTPException(status_code=400, detail="Для создания пар нужно минимум 2 участника")

        db.execute("DELETE FROM pairs")

        users = list(users)
        random.shuffle(users)

        created_pairs = []
        pairs_count = 0
        created_at = now_iso()

        for i in range(0, len(users) - 1, 2):
            meeting_start, meeting_end = default_meeting_times()

            db.execute("""
                INSERT INTO pairs (
                    user1_id,
                    user2_id,
                    created_at,
                    meeting_start,
                    meeting_end
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                users[i]["id"],
                users[i + 1]["id"],
                created_at,
                meeting_start,
                meeting_end
            ))

            pair_info = {
                "meeting_start": meeting_start,
                "meeting_end": meeting_end,
            }

            created_pairs.append((users[i], users[i + 1], pair_info))
            pairs_count += 1

        db.commit()

    for user1, user2, pair_info in created_pairs:
        send_match_email(user1, user2, pair_info)
        send_match_email(user2, user1, pair_info)

    return {"ok": True, "pairs_count": pairs_count}


@app.post("/api/pairs/reset")
def reset_pairs(x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        rows = db.execute("""
            SELECT DISTINCT u.email
            FROM users u
            JOIN pairs p ON p.user1_id = u.id OR p.user2_id = u.id
        """).fetchall()

        count = db.execute("SELECT COUNT(*) AS cnt FROM pairs").fetchone()["cnt"]
        db.execute("DELETE FROM pairs")
        db.commit()

    for row in rows:
        send_email_safe(
            row["email"],
            "Random Coffee — пары сброшены",
            "⚠️ Текущие Random Coffee пары были сброшены администратором. Новая пара будет назначена позже."
        )

    return {"ok": True, "reset_count": count, "notified_count": len(rows)}


def escape_ics_text(value: str) -> str:
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace(",", "\\,")
        .replace(";", "\\;")
        .replace("\n", "\\n")
    )


def build_ics(
    user1_name: str,
    user1_email: str,
    user2_name: str,
    user2_email: str,
    meeting_start: Optional[str] = None,
    meeting_end: Optional[str] = None,
) -> str:
    if meeting_start and meeting_end:
        start = datetime.fromisoformat(meeting_start)
        end = datetime.fromisoformat(meeting_end)
    else:
        meeting_start, meeting_end = default_meeting_times()
        start = datetime.fromisoformat(meeting_start)
        end = datetime.fromisoformat(meeting_end)

    dtstamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    dtstart = start.strftime("%Y%m%dT%H%M%S")
    dtend = end.strftime("%Y%m%dT%H%M%S")

    description = (
        f"{user1_name} — {user1_email}\n"
        f"{user2_name} — {user2_email}\n\n"
        "Рекомендуемая длительность: 15–30 минут."
    )

    return f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Mriya Random Coffee Web//RU
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VEVENT
UID:{uuid.uuid4()}
DTSTAMP:{dtstamp}
DTSTART:{dtstart}
DTEND:{dtend}
SUMMARY:Random Coffee
DESCRIPTION:{escape_ics_text(description)}
LOCATION:Online
ATTENDEE;CN={escape_ics_text(user1_name)};RSVP=TRUE:mailto:{user1_email}
ATTENDEE;CN={escape_ics_text(user2_name)};RSVP=TRUE:mailto:{user2_email}
END:VEVENT
END:VCALENDAR
"""


def send_email_safe(to_email: str, subject: str, body: str, ics_content: Optional[str] = None):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASSWORD or not SMTP_FROM:
        print(f"[EMAIL DISABLED] To: {to_email}; Subject: {subject}\n{body}\n")
        return False

    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    if ics_content:
        msg.add_attachment(
            ics_content.encode("utf-8"),
            maintype="text",
            subtype="calendar",
            filename="random-coffee.ics",
        )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            if SMTP_USE_TLS:
                smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as ex:
        print(f"[EMAIL ERROR] {to_email}: {ex}")
        return False


def send_match_email(current_user, partner, pair_info):
    meeting_start = pair_info.get("meeting_start")
    meeting_end = pair_info.get("meeting_end")
    meeting_time = format_meeting_time(meeting_start, meeting_end)

    ics = build_ics(
        current_user["full_name"],
        current_user["email"],
        partner["full_name"],
        partner["email"],
        meeting_start,
        meeting_end,
    )

    body = f"""
Привет, {current_user['full_name']}!

Твоя пара для Random Coffee ☕

Имя: {partner['full_name']}
Email: {partner['email']}
Отдел: {partner['department']}
Город: {partner['city']}

Время встречи:
{meeting_time}

Интересы:
{partner['interests']}

Во вложении файл встречи для Outlook.
""".strip()

    send_email_safe(
        current_user["email"],
        "Твой Random Coffee match ☕",
        body,
        ics,
    )


@app.get("/api/pairs/{pair_id}/ics")
def download_ics(pair_id: int, x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        row = db.execute("""
            SELECT
                p.id,
                u1.full_name AS user1_name,
                u1.email AS user1_email,
                u2.full_name AS user2_name,
                u2.email AS user2_email,
                p.meeting_start,
                p.meeting_end
            FROM pairs p
            JOIN users u1 ON u1.id = p.user1_id
            JOIN users u2 ON u2.id = p.user2_id
            WHERE p.id = ?
        """, (pair_id,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Пара не найдена")

    ics = build_ics(
        row["user1_name"],
        row["user1_email"],
        row["user2_name"],
        row["user2_email"],
        row["meeting_start"],
        row["meeting_end"],
    )

    return Response(
        content=ics,
        media_type="text/calendar",
        headers={"Content-Disposition": 'attachment; filename="random-coffee.ics"'},
    )


@app.get("/api/me/pair/ics")
def download_my_ics(x_user_token: Optional[str] = Header(default=None)):
    user = get_user_by_token(x_user_token)

    with get_db() as db:
        row = db.execute("""
            SELECT
                p.id,
                u1.full_name AS user1_name,
                u1.email AS user1_email,
                u2.full_name AS user2_name,
                u2.email AS user2_email,
                p.meeting_start,
                p.meeting_end
            FROM pairs p
            JOIN users u1 ON u1.id = p.user1_id
            JOIN users u2 ON u2.id = p.user2_id
            WHERE p.user1_id = ? OR p.user2_id = ?
            ORDER BY p.created_at DESC
            LIMIT 1
        """, (user["id"], user["id"])).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Пара не найдена")

    ics = build_ics(
        row["user1_name"],
        row["user1_email"],
        row["user2_name"],
        row["user2_email"],
        row["meeting_start"],
        row["meeting_end"],
    )

    return Response(
        content=ics,
        media_type="text/calendar",
        headers={"Content-Disposition": 'attachment; filename="random-coffee.ics"'},
    )
@app.get("/api/export/users.xlsx")
def export_users_excel(x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        rows = db.execute("""
            SELECT full_name, email, department, city, interests, created_at
            FROM users
            ORDER BY full_name
        """).fetchall()

    headers = ["Имя", "Email", "Отдел", "Город", "Интересы", "Дата регистрации"]
    data = [
        [
            row["full_name"],
            row["email"],
            row["department"],
            row["city"],
            row["interests"],
            row["created_at"],
            format_meeting_time(row["meeting_start"], row["meeting_end"]),
        ]
        for row in rows
    ]

    return xlsx_response("random-coffee-users.xlsx", build_xlsx(headers, data))


@app.get("/api/export/pairs.xlsx")
def export_pairs_excel(x_admin_password: Optional[str] = Header(default=None)):
    require_admin(x_admin_password)

    with get_db() as db:
        rows = db.execute("""
            SELECT
                u1.full_name AS user1_name,
                u1.email AS user1_email,
                u1.department AS user1_department,
                u1.city AS user1_city,
                u2.full_name AS user2_name,
                u2.email AS user2_email,
                u2.department AS user2_department,
                u2.city AS user2_city,
                p.created_at AS created_at,
                p.meeting_start AS meeting_start,
                p.meeting_end AS meeting_end
            FROM pairs p
            JOIN users u1 ON u1.id = p.user1_id
            JOIN users u2 ON u2.id = p.user2_id
            ORDER BY p.created_at DESC
        """).fetchall()

    headers = [
        "Участник 1",
        "Email 1",
        "Отдел 1",
        "Город 1",
        "Участник 2",
        "Email 2",
        "Отдел 2",
        "Город 2",
        "Дата создания пары",
        "Время встречи",
    ]

    data = [
        [
            row["user1_name"],
            row["user1_email"],
            row["user1_department"],
            row["user1_city"],
            row["user2_name"],
            row["user2_email"],
            row["user2_department"],
            row["user2_city"],
            row["created_at"],
            format_meeting_time(row["meeting_start"], row["meeting_end"]),
        ]
        for row in rows
    ]

    return xlsx_response("random-coffee-pairs.xlsx", build_xlsx(headers, data))


@app.get("/{full_path:path}")
def spa_fallback(full_path: str):
    if full_path.startswith("api/") or full_path.startswith("static/"):
        raise HTTPException(status_code=404, detail="Not found")

    return FileResponse(BASE_DIR / "static" / "index.html")


