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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} · 메모</title>
  <style>
    :root {
      color-scheme: light;
      font: 100%/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-optical-sizing: auto;
      --background: #f5f5f7;
      --surface: #fff;
      --text: #1d1d1f;
      --muted: #6e6e73;
      --border: #d8d8dd;
      --accent: #0066cc;
      --button-background: #0066cc;
      --button-hover: #0055ad;
      --focus: #007aff;
      --message: #eef6ff;
      --error: #fff0ef;
    }
    * { box-sizing: border-box; }
    body { min-height: 100svh; margin: 0; background: var(--background); color: var(--text); }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    a:focus-visible, button:focus-visible, input:focus-visible {
      outline: 3px solid var(--focus);
      outline-offset: 3px;
    }
    .shell { width: min(100%, 72rem); min-height: 100svh; margin: auto; padding: 1.5rem clamp(1.25rem, 4vw, 3rem); display: flex; flex-direction: column; }
    .site-header { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
    .brand { color: var(--text); font-size: 1.25rem; font-weight: 720; letter-spacing: -0.035em; }
    .brand:hover { text-decoration: none; }
    .site-label { color: var(--muted); font-size: .82rem; font-weight: 600; letter-spacing: .02em; }
    main { flex: 1; display: grid; place-items: center; padding: 2.5rem 0 4rem; }
    .panel { width: min(100%, 29rem); padding: clamp(1.75rem, 5vw, 2.75rem); background: var(--surface); border: 1px solid var(--border); border-radius: 1.5rem; box-shadow: 0 1.25rem 3rem rgba(20, 20, 30, .06); }
    .eyebrow { margin: 0 0 .85rem; color: var(--accent); font-size: .82rem; font-weight: 700; letter-spacing: .04em; }
    h1 { margin: 0; font-size: clamp(2rem, 7vw, 2.65rem); font-weight: 720; line-height: 1.15; letter-spacing: -.035em; overflow-wrap: anywhere; }
    .lead { margin: 1rem 0 0; color: var(--muted); line-height: 1.65; }
    .message { margin: 1.5rem 0 0; padding: .85rem 1rem; border-radius: .8rem; font-size: .93rem; }
    .message.notice { background: var(--message); }
    .message.error { background: var(--error); }
    .auth-form { margin-top: 2rem; }
    .field + .field { margin-top: 1.2rem; }
    label { display: block; margin-bottom: .5rem; font-size: .91rem; font-weight: 650; }
    input:not([type="hidden"]) { width: 100%; min-height: 3.15rem; padding: .75rem .95rem; border: 1px solid var(--border); border-radius: .85rem; background: var(--surface); color: var(--text); font: inherit; transition: border-color 150ms ease, box-shadow 150ms ease; }
    input:not([type="hidden"]):focus { border-color: var(--focus); box-shadow: 0 0 0 3px rgba(0, 122, 255, .13); outline: none; }
    input:not([type="hidden"]):focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
    .hint { display: block; margin-top: .5rem; color: var(--muted); font-size: .82rem; }
    .actions { display: grid; gap: .7rem; margin-top: 2rem; }
    .button { display: inline-flex; min-height: 3.15rem; align-items: center; justify-content: center; padding: .7rem 1.2rem; border: 1px solid transparent; border-radius: .85rem; font: inherit; font-weight: 650; cursor: pointer; text-align: center; transition: background-color 150ms ease, transform 100ms ease; }
    .button:hover { text-decoration: none; }
    .button:active { transform: scale(.975); }
    .button.primary { background: var(--button-background); color: #fff; }
    .button.primary:hover { background: var(--button-hover); }
    .button.secondary { border-color: var(--border); background: var(--surface); color: var(--text); }
    .button.secondary:hover { background: var(--background); }
    .switch { margin: 1.5rem 0 0; color: var(--muted); font-size: .91rem; text-align: center; }
    @media (max-width: 30rem) {
      .shell { padding: 1.1rem 1rem; }
      main { padding: 2rem 0; }
      .panel { border-radius: 1.25rem; }
    }
    @media (prefers-color-scheme: dark) {
      :root { color-scheme: dark; --background: #111113; --surface: #1c1c1e; --text: #f5f5f7; --muted: #b0b0b7; --border: #45454a; --accent: #0a84ff; --focus: #64b5ff; --message: #172b40; --error: #39201f; }
      .panel { box-shadow: 0 1.25rem 3rem rgba(0, 0, 0, .18); }
      .button.primary { color: #fff; }
    }
    @media (prefers-contrast: more) {
      .panel, input:not([type="hidden"]), .button.secondary { border: 2px solid var(--text); }
      .lead, .hint, .switch, .site-label { color: var(--text); }
    }
    @media (prefers-reduced-motion: reduce) {
      input:not([type="hidden"]), .button { transition: none; }
      .button:active { transform: none; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="site-header">
      <a class="brand" href="{{ url_for('index') }}">메모</a>
      <span class="site-label">나의 공간</span>
    </header>
    <main>
      <section class="panel" aria-labelledby="page-title">
        {% if page == "home" %}
          {% if username %}
            <p class="eyebrow">로그인 상태</p>
            <h1 id="page-title">안녕하세요,<br>{{ username }}님.</h1>
            <p class="lead">다시 오신 것을 환영합니다.</p>
            <form class="actions" method="post" action="{{ url_for('logout') }}">
              <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
              <button class="button secondary" type="submit">로그아웃</button>
            </form>
          {% else %}
            <p class="eyebrow">시작하기</p>
            <h1 id="page-title">메모 서비스에 오신 것을 환영합니다.</h1>
            <p class="lead">계정을 만들거나 로그인해 주세요.</p>
            <div class="actions">
              <a class="button primary" href="{{ url_for('register') }}">회원가입</a>
              <a class="button secondary" href="{{ url_for('login') }}">로그인</a>
            </div>
          {% endif %}
        {% else %}
          <p class="eyebrow">계정</p>
          <h1 id="page-title">{{ title }}</h1>
          {% if page == "register" %}
            <p class="lead">아이디와 비밀번호로 계정을 만드세요.</p>
          {% else %}
            <p class="lead">계정으로 다시 들어오세요.</p>
          {% endif %}
          {% if error %}<p class="message error" role="alert">{{ error }}</p>{% endif %}
          {% if notice %}<p class="message notice" role="status">{{ notice }}</p>{% endif %}
          <form class="auth-form" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <div class="field">
              <label for="username">아이디</label>
              <input id="username" name="username" autocomplete="username" required maxlength="30" {% if page == "register" %}minlength="3"{% endif %}>
            </div>
            <div class="field">
              <label for="password">비밀번호</label>
              <input id="password" type="password" name="password" autocomplete="{% if page == 'register' %}new-password{% else %}current-password{% endif %}" required {% if page == "register" %}minlength="8" maxlength="128" aria-describedby="password-hint"{% endif %}>
              {% if page == "register" %}<small class="hint" id="password-hint">8자 이상 입력해 주세요.</small>{% endif %}
            </div>
            <div class="actions"><button class="button primary" type="submit">{{ title }}</button></div>
          </form>
          {% if page == "register" %}
            <p class="switch">이미 계정이 있나요? <a href="{{ url_for('login') }}">로그인</a></p>
          {% else %}
            <p class="switch">계정이 없나요? <a href="{{ url_for('register') }}">회원가입</a></p>
          {% endif %}
        {% endif %}
      </section>
    </main>
  </div>
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
