import os
import secrets
import sqlite3
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.environ.get("DATABASE_PATH") or str(Path(__file__).with_name("users.db")),
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

PAGE = """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <title>{{ title }} - 메모 서비스</title>
</head>
<body>
  <h1>메모 서비스</h1>
  {% if error %}<p role="alert">{{ error }}</p>{% endif %}
  {% if notice %}<p>{{ notice }}</p>{% endif %}
  {% if page == "home" %}
    {% if username %}
      <p>{{ username }}님, 로그인 상태입니다.</p>
      <form method="post" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit">로그아웃</button>
      </form>
    {% else %}
      <p><a href="{{ url_for('register') }}">회원가입</a></p>
      <p><a href="{{ url_for('login') }}">로그인</a></p>
    {% endif %}
  {% else %}
    <h2>{{ title }}</h2>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
      <p><label>아이디 <input name="username" required maxlength="30"></label></p>
      <p><label>비밀번호 <input type="password" name="password" required></label></p>
      <button type="submit">{{ title }}</button>
    </form>
    {% if page == "register" %}
      <p><a href="{{ url_for('login') }}">이미 계정이 있나요? 로그인</a></p>
    {% else %}
      <p><a href="{{ url_for('register') }}">계정이 없나요? 회원가입</a></p>
    {% endif %}
    <p><a href="{{ url_for('index') }}">홈</a></p>
  {% endif %}
</body>
</html>"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY, "
            "username TEXT NOT NULL UNIQUE, "
            "password_hash TEXT NOT NULL)"
        )
        db.commit()


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def check_csrf():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(supplied, expected):
        abort(400)


def page(name, title, *, username=None, error=None, notice=None, status=200):
    return (
        render_template_string(
            PAGE,
            page=name,
            title=title,
            username=username,
            error=error,
            notice=notice,
            csrf_token=csrf_token(),
        ),
        status,
    )


@app.route("/")
def index():
    user_id = session.get("user_id")
    username = None
    if user_id is not None:
        user = get_db().execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None:
            session.clear()
        else:
            username = user["username"]
    return page("home", "홈", username=username)


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id") is not None:
        return redirect(url_for("index"))
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not 3 <= len(username) <= 30 or any(char.isspace() for char in username):
            return page("register", "회원가입", error="아이디는 공백 없이 3~30자로 입력하세요.", status=400)
        if not 8 <= len(password) <= 128:
            return page("register", "회원가입", error="비밀번호는 8~128자로 입력하세요.", status=400)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return page("register", "회원가입", error="이미 사용 중인 아이디입니다.", status=409)
        return redirect(url_for("login", registered=1))
    return page("register", "회원가입")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id") is not None:
        return redirect(url_for("index"))
    if request.method == "POST":
        check_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            return page("login", "로그인", error="아이디 또는 비밀번호가 올바르지 않습니다.", status=401)
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        return redirect(url_for("index"))
    notice = None
    if request.args.get("registered") == "1":
        notice = "회원가입이 완료되었습니다. 로그인하세요."
    elif request.args.get("logged_out") == "1":
        notice = "로그아웃되었습니다."
    return page("login", "로그인", notice=notice)


@app.post("/logout")
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login", logged_out=1))


init_db()

if __name__ == "__main__":
    app.run()
