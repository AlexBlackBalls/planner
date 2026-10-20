"""Планировщик дня: бэкенд (FastAPI + SQLite).

Запуск:      uvicorn app:app --host 127.0.0.1 --port 8000
Код-приглашение: python app.py invite
"""
import asyncio
import hashlib
import os
import secrets
import sqlite3
import sys
from contextlib import asynccontextmanager, closing
from datetime import date, timedelta
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

DB_PATH = os.environ.get("PLANNER_DB", "planner.db")
RETENTION_DAYS = 14          # сколько дней хранить просроченные задачи
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"  # включить за HTTPS

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
    salt TEXT NOT NULL, pw_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY, used_by INTEGER);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    due_date TEXT NOT NULL,          -- YYYY-MM-DD
    due_time TEXT,                   -- HH:MM, необязательно
    done INTEGER NOT NULL DEFAULT 0,
    moves INTEGER NOT NULL DEFAULT 0, -- сколько раз задачу переносили
    important INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tasks_user_date ON tasks(user_id, due_date);
CREATE TABLE IF NOT EXISTS notes (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    text TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS habits (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS habit_log (
    habit_id INTEGER NOT NULL REFERENCES habits(id) ON DELETE CASCADE,
    day TEXT NOT NULL,
    PRIMARY KEY (habit_id, day));
CREATE TABLE IF NOT EXISTS activity (   -- сколько задач выполнено в день (для тепловой карты)
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day TEXT NOT NULL,
    n INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day));
"""


def run(sql, args=(), *, one=False, fetch=False):
    with closing(sqlite3.connect(DB_PATH)) as con:
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        cur = con.execute(sql, args)
        rows = cur.fetchall() if fetch or one else None
        con.commit()
        last = cur.lastrowid
        changed = cur.rowcount
    if one:
        return rows[0] if rows else None
    return rows if fetch else (last, changed)


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as con:
        con.executescript(SCHEMA)
        cols = [r[1] for r in con.execute("PRAGMA table_info(tasks)")]
        if "important" not in cols:  # обновление старой базы
            con.execute("ALTER TABLE tasks ADD COLUMN important INTEGER NOT NULL DEFAULT 0")
            con.commit()
        if con.execute("SELECT COUNT(*) FROM activity").fetchone()[0] == 0:
            con.execute("INSERT OR IGNORE INTO activity (user_id, day, n) "
                        "SELECT user_id, due_date, COUNT(*) FROM tasks WHERE done = 1 GROUP BY user_id, due_date")
            con.commit()


def cleanup_old_tasks():
    """Удаляет задачи, срок которых истёк более RETENTION_DAYS дней назад."""
    limit = (date.today() - timedelta(days=RETENTION_DAYS)).isoformat()
    old = (date.today() - timedelta(days=120)).isoformat()
    run("DELETE FROM habit_log WHERE day < ?", (old,))
    run("DELETE FROM activity WHERE day < ?", (old,))
    return run("DELETE FROM tasks WHERE due_date < ?", (limit,))[1]


async def cleanup_loop():
    while True:
        cleanup_old_tasks()
        await asyncio.sleep(24 * 3600)


@asynccontextmanager
async def lifespan(_):
    init_db()
    task = asyncio.create_task(cleanup_loop())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)


# ---------- пароли и сессии ----------
def hash_pw(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def current_user(request: Request) -> int:
    token = request.cookies.get("session")
    row = run("SELECT user_id FROM sessions WHERE token = ?", (token,), one=True) if token else None
    if not row:
        raise HTTPException(401, "Нужно войти")
    return row["user_id"]


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)


class Register(Credentials):
    invite: str


def start_session(response: Response, user_id: int):
    token = secrets.token_urlsafe(32)
    run("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id))
    response.set_cookie("session", token, httponly=True, samesite="lax",
                        secure=COOKIE_SECURE, max_age=30 * 24 * 3600)


@app.post("/api/register")
def register(data: Register, response: Response):
    inv = run("SELECT code FROM invites WHERE code = ? AND used_by IS NULL", (data.invite,), one=True)
    if not inv:
        raise HTTPException(403, "Неверный или уже использованный код приглашения")
    salt = secrets.token_bytes(16)
    try:
        uid, _ = run("INSERT INTO users (username, salt, pw_hash) VALUES (?, ?, ?)",
                     (data.username, salt.hex(), hash_pw(data.password, salt)))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Такое имя уже занято")
    run("UPDATE invites SET used_by = ? WHERE code = ?", (uid, data.invite))
    start_session(response, uid)
    return {"ok": True}


@app.post("/api/login")
def login(data: Credentials, response: Response):
    u = run("SELECT * FROM users WHERE username = ?", (data.username,), one=True)
    if not u or not secrets.compare_digest(
            u["pw_hash"], hash_pw(data.password, bytes.fromhex(u["salt"]))):
        raise HTTPException(401, "Неверное имя или пароль")
    start_session(response, u["id"])
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response):
    run("DELETE FROM sessions WHERE token = ?", (request.cookies.get("session"),))
    response.delete_cookie("session")
    return {"ok": True}


# ---------- задачи ----------
class TaskIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    due_date: date
    due_time: Optional[str] = Field(default=None, pattern=r"^\d{2}:\d{2}$")
    important: bool = False


class TaskPatch(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    done: Optional[bool] = None
    important: Optional[bool] = None


class MoveIn(BaseModel):
    new_date: date


def owned_task(task_id: int, uid: int):
    t = run("SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, uid), one=True)
    if not t:
        raise HTTPException(404, "Задача не найдена")
    return t


@app.get("/api/tasks")
def list_tasks(day: date, days: int = 1, uid: int = Depends(current_user)):
    end = day + timedelta(days=max(1, min(days, 31)) - 1)
    rows = run("SELECT * FROM tasks WHERE user_id = ? AND due_date BETWEEN ? AND ? "
               "ORDER BY due_date, important DESC, due_time IS NULL, due_time, id",
               (uid, day.isoformat(), end.isoformat()), fetch=True)
    return [dict(r) for r in rows]


@app.get("/api/upcoming")
def upcoming(since: date, uid: int = Depends(current_user)):
    """Невыполненные события от даты since: сначала важные, затем по времени."""
    rows = run("SELECT * FROM tasks WHERE user_id = ? AND done = 0 AND due_date >= ? "
               "ORDER BY important DESC, due_date, due_time IS NULL, due_time, id LIMIT 30",
               (uid, since.isoformat()), fetch=True)
    return [dict(r) for r in rows]


@app.post("/api/tasks", status_code=201)
def add_task(data: TaskIn, uid: int = Depends(current_user)):
    tid, _ = run("INSERT INTO tasks (user_id, title, due_date, due_time, important) "
                 "VALUES (?, ?, ?, ?, ?)",
                 (uid, data.title, data.due_date.isoformat(), data.due_time, int(data.important)))
    return {"id": tid}


@app.patch("/api/tasks/{task_id}")
def update_task(task_id: int, data: TaskPatch, uid: int = Depends(current_user)):
    t = owned_task(task_id, uid)
    title = data.title if data.title is not None else t["title"]
    done = int(data.done) if data.done is not None else t["done"]
    imp = int(data.important) if data.important is not None else t["important"]
    run("UPDATE tasks SET title = ?, done = ?, important = ? WHERE id = ?", (title, done, imp, task_id))
    if done != t["done"]:
        bump(uid, t["due_date"], 1 if done else -1)
    return {"ok": True}


@app.post("/api/tasks/{task_id}/move")
def move_task(task_id: int, data: MoveIn, uid: int = Depends(current_user)):
    t = owned_task(task_id, uid)
    if data.new_date.isoformat() == t["due_date"]:
        raise HTTPException(400, "Задача уже на эту дату")
    if t["done"]:
        bump(uid, t["due_date"], -1)
    run("UPDATE tasks SET due_date = ?, done = 0, moves = moves + 1 WHERE id = ?",
        (data.new_date.isoformat(), task_id))
    return {"ok": True}


@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int, uid: int = Depends(current_user)):
    owned_task(task_id, uid)
    run("DELETE FROM tasks WHERE id = ?", (task_id,))
    return {"ok": True}


def bump(uid, day, delta):
    run("INSERT INTO activity (user_id, day, n) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id, day) DO UPDATE SET n = MAX(0, n + ?)",
        (uid, day, max(delta, 0), delta))


# ---------- заметки ----------
class NotesIn(BaseModel):
    text: str = Field(max_length=5000)


@app.get("/api/notes")
def get_notes(uid: int = Depends(current_user)):
    row = run("SELECT text FROM notes WHERE user_id = ?", (uid,), one=True)
    return {"text": row["text"] if row else ""}


@app.put("/api/notes")
def put_notes(data: NotesIn, uid: int = Depends(current_user)):
    run("INSERT INTO notes (user_id, text) VALUES (?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET text = excluded.text", (uid, data.text))
    return {"ok": True}


# ---------- привычки ----------
class HabitIn(BaseModel):
    name: str = Field(min_length=1, max_length=60)


class ToggleIn(BaseModel):
    day: date


def owned_habit(habit_id: int, uid: int):
    h = run("SELECT * FROM habits WHERE id = ? AND user_id = ?", (habit_id, uid), one=True)
    if not h:
        raise HTTPException(404, "Привычка не найдена")
    return h


@app.get("/api/habits")
def list_habits(start: date, today: date, uid: int = Depends(current_user)):
    """Привычки с отметками на неделю с даты start и текущей серией (дней подряд)."""
    since = (today - timedelta(days=120)).isoformat()
    out = []
    for h in run("SELECT id, name FROM habits WHERE user_id = ? ORDER BY id", (uid,), fetch=True):
        logs = {r["day"] for r in run("SELECT day FROM habit_log WHERE habit_id = ? AND day >= ?",
                                       (h["id"], since), fetch=True)}
        d = today if today.isoformat() in logs else today - timedelta(days=1)
        streak = 0
        while d.isoformat() in logs:
            streak += 1
            d -= timedelta(days=1)
        week = [(start + timedelta(days=i)).isoformat() in logs for i in range(7)]
        out.append({"id": h["id"], "name": h["name"], "week": week, "streak": streak})
    return out


@app.post("/api/habits", status_code=201)
def add_habit(data: HabitIn, uid: int = Depends(current_user)):
    if run("SELECT COUNT(*) AS c FROM habits WHERE user_id = ?", (uid,), one=True)["c"] >= 10:
        raise HTTPException(400, "Не больше 10 привычек")
    hid, _ = run("INSERT INTO habits (user_id, name) VALUES (?, ?)", (uid, data.name.strip()))
    return {"id": hid}


@app.delete("/api/habits/{habit_id}")
def delete_habit(habit_id: int, uid: int = Depends(current_user)):
    owned_habit(habit_id, uid)
    run("DELETE FROM habits WHERE id = ?", (habit_id,))
    return {"ok": True}


@app.post("/api/habits/{habit_id}/toggle")
def toggle_habit(habit_id: int, data: ToggleIn, uid: int = Depends(current_user)):
    owned_habit(habit_id, uid)
    day = data.day.isoformat()
    if run("DELETE FROM habit_log WHERE habit_id = ? AND day = ?", (habit_id, day))[1] == 0:
        run("INSERT INTO habit_log (habit_id, day) VALUES (?, ?)", (habit_id, day))
    return {"ok": True}


# ---------- тепловая карта ----------
@app.get("/api/heatmap")
def heatmap(end: date, weeks: int = 15, uid: int = Depends(current_user)):
    """{день: сколько задач выполнено + сколько отметок привычек} за последние недели."""
    since = (end - timedelta(days=7 * max(1, min(weeks, 17)))).isoformat()
    counts = {}
    for r in run("SELECT day, n FROM activity WHERE user_id = ? AND day >= ?", (uid, since), fetch=True):
        counts[r["day"]] = r["n"]
    for r in run("SELECT l.day AS day, COUNT(*) AS n FROM habit_log l JOIN habits h ON h.id = l.habit_id "
                 "WHERE h.user_id = ? AND l.day >= ? GROUP BY l.day", (uid, since), fetch=True):
        counts[r["day"]] = counts.get(r["day"], 0) + r["n"]
    return counts


# ---------- веб-страница ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/hero.png", include_in_schema=False)
def hero():
    return FileResponse(os.path.join(BASE_DIR, "hero.png"))


if __name__ == "__main__":
    if sys.argv[1:] == ["invite"]:
        init_db()
        code = secrets.token_urlsafe(8)
        run("INSERT INTO invites (code) VALUES (?)", (code,))
        print("Код-приглашение (одноразовый):", code)
    else:
        print("Использование: python app.py invite")
