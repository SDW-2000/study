"""Run locally with .venv/bin/python app.py.

For HTTPS deployment, set APP_ENV=production, a random SECRET_KEY (32+ bytes),
and TRUSTED_HOSTS (comma-separated hostnames) in the server environment.
Use a production WSGI server; configure HTTPS at the server or trusted proxy.
"""

import hashlib
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template_string, request, session, url_for
from werkzeug.exceptions import HTTPException, TooManyRequests
from werkzeug.security import check_password_hash, generate_password_hash


environment = os.environ.get("APP_ENV", "development")
if environment not in {"development", "production"}:
    raise RuntimeError("APP_ENV must be development or production.")
production = environment == "production"
secret_key = os.environ.get("SECRET_KEY")
trusted_hosts = [host.strip() for host in os.environ.get("TRUSTED_HOSTS", "").split(",") if host.strip()]
if secret_key is not None and len(secret_key.encode("utf-8")) < 32:
    raise RuntimeError("SECRET_KEY must contain at least 32 random bytes.")
if production and (not secret_key or not trusted_hosts):
    raise RuntimeError("Production requires SECRET_KEY and TRUSTED_HOSTS.")

PASSWORD_MIN_LENGTH = 15
PASSWORD_MAX_LENGTH = 128
TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}")
AUTH_LIMITS = {"login": (10, 300), "register": (5, 3600)}
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_hex(32))

app = Flask(__name__, static_folder=None)
app.config.update(
    SECRET_KEY=secret_key or secrets.token_hex(32),
    DATABASE=os.environ.get("DATABASE_PATH") or str(Path(__file__).with_name("users.db")),
    PRODUCTION=production,
    DEBUG=False,
    TRUSTED_HOSTS=trusted_hosts or ["localhost", "127.0.0.1", "[::1]"],
    MAX_CONTENT_LENGTH=16 * 1024,
    MAX_FORM_MEMORY_SIZE=16 * 1024,
    MAX_FORM_PARTS=3,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_REFRESH_EACH_REQUEST=False,
    SESSION_COOKIE_NAME="__Host-memo_session" if production else "memo_session",
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_SECURE=production,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

PAGE = """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} · 메모</title>
  <style nonce="{{ csp_nonce }}">
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
      <a class="brand" href="{{ '/' if page == 'error' else url_for('index') }}">메모</a>
      <span class="site-label">나의 공간</span>
    </header>
    <main>
      <section class="panel" aria-labelledby="page-title">
        {% if page == "error" %}
          <p class="eyebrow">요청 안내</p>
          <h1 id="page-title">{{ title }}</h1>
          <p class="message error" role="alert">{{ error }}</p>
          <div class="actions"><a class="button secondary" href="/">홈으로 돌아가기</a></div>
        {% elif page == "home" %}
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
              <input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength="30" {% if page == "register" %}minlength="3" aria-describedby="username-hint"{% endif %}>
              {% if page == "register" %}<small class="hint" id="username-hint">3~30자. 글자, 숫자, 밑줄(_), 점(.), 하이픈(-)을 사용할 수 있어요.</small>{% endif %}
            </div>
            <div class="field">
              <label for="password">비밀번호</label>
              <input id="password" type="password" name="password" autocomplete="{% if page == 'register' %}new-password{% else %}current-password{% endif %}" required maxlength="{{ password_max_length }}" {% if page == "register" %}minlength="{{ password_min_length }}" aria-describedby="password-hint"{% endif %}>
              {% if page == "register" %}<small class="hint" id="password-hint">{{ password_min_length }}~{{ password_max_length }}자. 여러 단어를 조합해 보세요.</small>{% endif %}
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
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db_path = Path(app.config["DATABASE"])
    descriptor = os.open(db_path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(descriptor)
    db_path.chmod(0o600)
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS auth_sessions_expiry ON auth_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS auth_limits (
                key TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL,
                resets_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS auth_limits_expiry ON auth_limits(resets_at);
        """)


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def enforce_auth_limit():
    limit, window = AUTH_LIMITS[request.endpoint]
    # Use the actual peer address. Forwarded headers are not trusted by default.
    source = f"{request.endpoint}:{request.remote_addr or 'unknown'}"
    key = hashlib.sha256(source.encode("utf-8")).hexdigest()
    now = int(time.time())
    db = get_db()
    # SQLite serializes this write transaction, including across WSGI workers.
    with db:
        db.execute("DELETE FROM auth_limits WHERE resets_at <= ?", (now,))
        db.execute(
            "INSERT INTO auth_limits (key, attempts, resets_at) VALUES (?, 1, ?) "
            "ON CONFLICT(key) DO UPDATE SET attempts = MIN(auth_limits.attempts + 1, ?)",
            (key, now + window, limit + 1),
        )
        entry = db.execute("SELECT attempts, resets_at FROM auth_limits WHERE key = ?", (key,)).fetchone()
    if entry["attempts"] > limit:
        raise TooManyRequests(retry_after=max(1, entry["resets_at"] - now))


@app.before_request
def prepare_request():
    g.csp_nonce = secrets.token_urlsafe(24)
    g.user = None
    if request.routing_exception is not None:
        return
    if app.config["PRODUCTION"] and not request.is_secure:
        abort(400)
    if request.method == "POST":
        if request.mimetype != "application/x-www-form-urlencoded":
            abort(415)
        fields = {"csrf_token"} if request.endpoint == "logout" else {"csrf_token", "username", "password"}
        if set(request.form) != fields or any(len(request.form.getlist(field)) != 1 for field in fields):
            abort(400)
        check_csrf()
        if request.endpoint in AUTH_LIMITS:
            enforce_auth_limit()

    token = session.get("auth_token")
    if token is None:
        return
    if not isinstance(token, str) or TOKEN_PATTERN.fullmatch(token) is None:
        session.clear()
        return
    db = get_db()
    digest = token_digest(token)
    g.user = db.execute(
        "SELECT users.id, users.username FROM auth_sessions "
        "JOIN users ON users.id = auth_sessions.user_id "
        "WHERE auth_sessions.token_hash = ? AND auth_sessions.expires_at > ?",
        (digest, int(time.time())),
    ).fetchone()
    if g.user is None:
        with db:
            db.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (digest,))
        session.clear()


@app.after_request
def secure_response(response):
    nonce = getattr(g, "csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src 'nonce-{nonce}'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if app.config["PRODUCTION"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.errorhandler(HTTPException)
@app.errorhandler(500)
def safe_error_response(error):
    messages = {
        400: "요청을 확인할 수 없습니다. 페이지를 새로 열고 다시 시도해 주세요.",
        404: "요청한 페이지를 찾을 수 없습니다.",
        405: "지원하지 않는 요청 방식입니다.",
        413: "입력한 데이터가 너무 큽니다.",
        415: "화면의 입력 양식을 사용해 주세요.",
        429: "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
        500: "요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.",
    }
    response = error.get_response()
    html, _ = page("error", "요청을 처리할 수 없어요", error=messages.get(error.code, messages[400]), status=error.code)
    response.set_data(html)
    response.content_type = "text/html; charset=utf-8"
    return response


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def check_csrf():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if (
        TOKEN_PATTERN.fullmatch(supplied) is None
        or not isinstance(expected, str)
        or TOKEN_PATTERN.fullmatch(expected) is None
        or not secrets.compare_digest(supplied, expected)
    ):
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
            csrf_token=csrf_token() if name != "error" else "",
            csp_nonce=g.csp_nonce,
            password_min_length=PASSWORD_MIN_LENGTH,
            password_max_length=PASSWORD_MAX_LENGTH,
        ),
        status,
    )


@app.route("/")
def index():
    return page("home", "홈", username=g.user["username"] if g.user else None)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not 3 <= len(username) <= 30 or not all(char.isalnum() or char in "_.-" for char in username):
            return page("register", "회원가입", error="아이디는 3~30자의 글자, 숫자, 밑줄, 점, 하이픈으로 입력하세요.", status=400)
        if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
            return page("register", "회원가입", error=f"비밀번호는 {PASSWORD_MIN_LENGTH}~{PASSWORD_MAX_LENGTH}자로 입력하세요.", status=400)
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
    if g.user is not None:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        invalid_login = "아이디 또는 비밀번호가 올바르지 않습니다."
        if not 3 <= len(username) <= 30 or not 1 <= len(password) <= PASSWORD_MAX_LENGTH:
            return page("login", "로그인", error=invalid_login, status=401)
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        password_matches = check_password_hash(user["password_hash"] if user else DUMMY_PASSWORD_HASH, password)
        if user is None or not password_matches:
            return page("login", "로그인", error=invalid_login, status=401)
        token = secrets.token_hex(32)
        now = int(time.time())
        expires_at = now + int(app.permanent_session_lifetime.total_seconds())
        db = get_db()
        with db:
            db.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))
            db.execute(
                "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (token_digest(token), user["id"], expires_at),
            )
        session.clear()
        session["auth_token"] = token
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
    token = session.get("auth_token")
    if token is not None:
        db = get_db()
        with db:
            db.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (token_digest(token),))
    session.clear()
    return redirect(url_for("login", logged_out=1))


init_db()

if __name__ == "__main__":
    if production:
        raise RuntimeError("Use a production WSGI server with HTTPS instead of app.run().")
    app.run(host="127.0.0.1", debug=False)
