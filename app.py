"""Run locally with .venv/bin/python app.py.

On the first launch, set ADMIN_PASSWORD (15-128 characters) to seed the admin
account. ADMIN_NOTE may provide an initial SBOB{...} note; both are used once.
For HTTPS deployment, set APP_ENV=production, a random SECRET_KEY (32+ bytes),
and TRUSTED_HOSTS (comma-separated hostnames) in the server environment.
Use a production WSGI server; configure HTTPS at the server or trusted proxy.
"""

import hashlib
import ipaddress
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, abort, g, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.exceptions import HTTPException, TooManyRequests
from werkzeug.middleware.proxy_fix import ProxyFix
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
trust_proxy = os.environ.get("TRUST_PROXY", "0")
if trust_proxy not in {"0", "1"}:
    raise RuntimeError("TRUST_PROXY must be 0 or 1.")
audit_retention_days = os.environ.get("AUDIT_RETENTION_DAYS", "90")
if re.fullmatch(r"[0-9]{1,3}", audit_retention_days) is None or not 7 <= int(audit_retention_days) <= 365:
    raise RuntimeError("AUDIT_RETENTION_DAYS must be an integer between 7 and 365.")

PASSWORD_MIN_LENGTH = 15
PASSWORD_MAX_LENGTH = 128
NOTE_TITLE_MAX_LENGTH = 120
NOTE_CONTENT_MAX_LENGTH = 10000
NOTE_TIMEZONE = timezone(timedelta(hours=9))
PAGE_SIZE = 20
AUDIT_PAGE_SIZE = 50
TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}")
REQUEST_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
AUDIT_EVENT_TYPES = {
    "auth.login", "auth.logout", "account.register", "account.password_change",
    "admin.member_password_change", "authorization.admin_denied",
    "note.create", "note.update", "note.delete",
}
AUDIT_OUTCOMES = {"success", "failure", "denied", "rate_limited"}
AUDIT_CHANNELS = {"web", "api"}
AUDIT_REASON_CODES = {
    None, "invalid_input", "invalid_credentials", "username_conflict",
    "current_password_mismatch", "confirmation_mismatch", "password_reused",
    "concurrent_change", "rate_limit", "admin_required",
}
AUTH_LIMITS = {
    "login": (10, 300), "register": (5, 3600),
    "change_password": (5, 300), "admin_change_password": (5, 300),
    "api_create_note": (30, 60),
}
POST_FIELDS = {
    "register": {"csrf_token", "username", "password"},
    "login": {"csrf_token", "username", "password"},
    "logout": {"csrf_token"},
    "create_note": {"csrf_token", "title", "content"},
    "edit_note": {"csrf_token", "title", "content"},
    "delete_note": {"csrf_token"},
    "change_password": {"csrf_token", "current_password", "new_password", "confirm_password"},
    "admin_change_password": {"csrf_token", "current_password", "new_password", "confirm_password"},
}
DUMMY_PASSWORD_HASH = generate_password_hash(secrets.token_hex(32))

app = Flask(__name__, static_folder="static")
app.config.update(
    SECRET_KEY=secret_key or secrets.token_hex(32),
    DATABASE=os.environ.get("DATABASE_PATH") or str(Path(__file__).with_name("users.db")),
    AUDIT_RETENTION_DAYS=int(audit_retention_days),
    PRODUCTION=production,
    DEBUG=False,
    TRUSTED_HOSTS=trusted_hosts or ["localhost", "127.0.0.1", "[::1]"],
    MAX_CONTENT_LENGTH=128 * 1024,
    MAX_FORM_MEMORY_SIZE=128 * 1024,
    MAX_FORM_PARTS=3,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_REFRESH_EACH_REQUEST=False,
    SESSION_COOKIE_NAME="__Host-memo_session" if production else "memo_session",
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_SECURE=production,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
audit_cleanup_lock = threading.Lock()
audit_cleanup_deadline = 0.0
if trust_proxy == "1":
    # Only enable behind the single Caddy proxy on the private Docker network.
    # Caddy replaces client-supplied forwarding headers; port 8000 is not published.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0, x_port=0, x_prefix=0)

PAGE = """<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} · 메모</title>
  <link rel="icon" href="{{ '/static/favicon.ico' if page == 'error' else url_for('static', filename='favicon.ico') }}" type="image/x-icon">
  {% if page == 'audit' %}<script defer src="{{ url_for('static', filename='admin_audit.js') }}"></script>{% endif %}
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
      --toolbar: rgba(245, 245, 247, .9);
    }
    * { box-sizing: border-box; }
    body { min-height: 100svh; margin: 0; background: var(--background); color: var(--text); }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible, summary:focus-visible {
      outline: 3px solid var(--focus);
      outline-offset: 3px;
    }
    .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
    .shell { width: min(100%, 72rem); min-height: 100svh; margin: auto; padding: 1.5rem clamp(1.25rem, 4vw, 3rem); display: flex; flex-direction: column; }
    .site-header { position: sticky; top: 0; z-index: 1; display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: .6rem 0; background: var(--toolbar); backdrop-filter: blur(20px) saturate(150%); -webkit-backdrop-filter: blur(20px) saturate(150%); }
    .brand { display: inline-flex; align-items: center; min-height: 2.75rem; flex-shrink: 0; color: var(--text); font-size: 1.25rem; font-weight: 720; letter-spacing: -0.035em; }
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
    select { width: 100%; min-height: 2.8rem; padding: .6rem 2rem .6rem .8rem; border: 1px solid var(--border); border-radius: .75rem; background-color: var(--surface); color: var(--text); font: inherit; }
    input:not([type="hidden"]):focus { border-color: var(--focus); box-shadow: 0 0 0 3px rgba(0, 122, 255, .13); outline: none; }
    input:not([type="hidden"]):focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
    .hint { display: block; margin-top: .5rem; color: var(--muted); font-size: .82rem; }
    .actions { display: grid; gap: .7rem; margin-top: 2rem; }
    .button { display: inline-flex; min-height: 3.15rem; align-items: center; justify-content: center; padding: .7rem 1.2rem; border: 1px solid transparent; border-radius: .85rem; font: inherit; font-weight: 650; cursor: pointer; touch-action: manipulation; text-align: center; transition: background-color 150ms ease, transform 100ms ease; }
    .button:hover { text-decoration: none; }
    .button:active { transform: scale(.975); }
    .button.primary { background: var(--button-background); color: #fff; }
    .button.primary:hover { background: var(--button-hover); }
    .button.secondary { border-color: var(--border); background: var(--surface); color: var(--text); }
    .button.secondary:hover { background: var(--background); }
    .switch { margin: 1.5rem 0 0; color: var(--muted); font-size: .91rem; text-align: center; }
    .account-nav { display: flex; flex-wrap: wrap; align-items: center; justify-content: flex-end; gap: .4rem; font-size: .9rem; font-weight: 550; }
    .account-nav > a { display: inline-flex; min-height: 2.75rem; align-items: center; padding: .5rem .8rem; color: var(--text); border-radius: .75rem; }
    .account-nav > a:hover, .account-nav > a:active, .account-nav > a[aria-current] { background: var(--surface); text-decoration: none; }
    .account-nav > a[aria-current] { box-shadow: 0 1px 3px rgba(0, 0, 0, .08); font-weight: 700; }
    .account-nav form { margin: 0; }
    .button.compact { min-height: 2.75rem; padding: .5rem .9rem; font-size: .9rem; }
    main.workspace { place-items: start center; }
    .panel-wide { width: min(100%, 52rem); min-width: 0; }
    .panel-audit { width: 100%; min-width: 0; padding: clamp(1.25rem, 3vw, 2rem); }
    .section-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 1.5rem; }
    .section-heading > div { min-width: 0; }
    .note-list { list-style: none; padding: 0; margin: 2rem 0 0; }
    .note-list li + li { border-top: 1px solid var(--border); }
    .note-link { display: block; padding: 1.25rem .75rem; color: var(--text); border-radius: .75rem; touch-action: manipulation; transition: background-color 120ms ease; }
    .note-link:hover { text-decoration: none; background: var(--background); }
    .note-link:active { background: var(--message); }
    .note-link h2 { margin: 0; font-size: 1.15rem; letter-spacing: -.02em; overflow-wrap: anywhere; }
    .preview { margin: .55rem 0; color: var(--muted); overflow-wrap: anywhere; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
    .note-meta { color: var(--muted); font-size: .8rem; letter-spacing: .01em; font-variant-numeric: tabular-nums; }
    .note-content { margin: 2rem 0; white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.8; }
    .empty-content { color: var(--muted); }
    textarea { display: block; width: 100%; min-height: 18rem; resize: vertical; padding: .85rem 1rem; border: 1px solid var(--border); border-radius: .85rem; background: var(--surface); color: var(--text); font: inherit; line-height: 1.7; }
    textarea:focus { border-color: var(--focus); }
    .inline-actions { display: flex; flex-wrap: wrap; gap: .7rem; margin-top: 1.5rem; }
    .inline-actions .button { flex: 1 1 7rem; }
    .button.danger { color: #fff; background: #b42318; }
    .button.danger:hover { background: #912018; }
    .empty-state { padding: 3.5rem 1rem; margin-top: 2rem; border-radius: 1rem; background: var(--background); text-align: center; }
    .empty-state h2 { margin: 0; font-size: 1.2rem; letter-spacing: -.02em; }
    .empty-state .lead { margin-top: .65rem; }
    .pagination { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 1rem; border-top: 1px solid var(--border); margin-top: 1.5rem; padding-top: 1.5rem; }
    .table-wrap { overflow-x: auto; margin-top: 2rem; }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th { color: var(--muted); font-size: .85rem; font-weight: 650; }
    th, td { padding: 1rem .5rem; border-bottom: 1px solid var(--border); }
    td.member-name { overflow-wrap: anywhere; }
    .role-label { white-space: nowrap; font-size: .9rem; }
    .audit-heading-tools { display: flex; flex-wrap: wrap; align-items: center; justify-content: flex-end; gap: .6rem; }
    .audit-status { display: inline-flex; align-items: center; gap: .45rem; min-height: 2.75rem; color: var(--muted); font-size: .82rem; font-weight: 650; white-space: nowrap; }
    .audit-status::before { width: .5rem; height: .5rem; border-radius: 50%; background: #218739; content: ""; box-shadow: 0 0 0 3px rgba(33, 135, 57, .12); }
    .audit-status[data-state="paused"]::before { background: #9b6a00; box-shadow: 0 0 0 3px rgba(155, 106, 0, .12); }
    .audit-status[data-state="error"]::before { background: #b42318; box-shadow: 0 0 0 3px rgba(180, 35, 24, .12); }
    .audit-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin: 2rem 0 0; border: 1px solid var(--border); border-radius: 1rem; overflow: hidden; }
    .audit-metric { min-width: 0; padding: 1rem 1.1rem; background: var(--background); }
    .audit-metric + .audit-metric { border-left: 1px solid var(--border); }
    .audit-metric dt { color: var(--muted); font-size: .8rem; font-weight: 650; }
    .audit-metric dd { margin: .3rem 0 0; font-size: 1.65rem; font-weight: 720; line-height: 1.15; letter-spacing: -.03em; font-variant-numeric: tabular-nums; }
    .audit-filters { margin-top: 1.25rem; padding: 1rem; border: 0; border-radius: 1rem; background: var(--background); }
    .audit-filter-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: .8rem; }
    .audit-filter-grid label { font-size: .78rem; }
    .audit-filter-actions { display: flex; flex-wrap: wrap; align-items: center; gap: .7rem; margin-top: 1rem; }
    .audit-table { table-layout: fixed; }
    .audit-table th:nth-child(1) { width: 9.5rem; }
    .audit-table th:nth-child(2) { width: 5rem; }
    .audit-table th:nth-child(3) { width: 10rem; }
    .audit-table th:nth-child(5) { width: 9rem; }
    .audit-table th:nth-child(6) { width: 4.5rem; }
    .audit-table td { vertical-align: top; font-size: .9rem; overflow-wrap: anywhere; }
    .audit-time, .audit-ip { white-space: nowrap; font-size: .82rem; font-variant-numeric: tabular-nums; }
    .audit-secondary { display: block; margin-top: .25rem; color: var(--muted); font-size: .77rem; line-height: 1.45; }
    .audit-badge { display: inline-flex; align-items: center; gap: .35rem; min-height: 1.7rem; padding: .18rem .55rem; border-radius: 999px; font-size: .77rem; font-weight: 700; white-space: nowrap; }
    .audit-badge::before { width: .42rem; height: .42rem; border-radius: 50%; content: ""; background: currentColor; }
    .audit-badge.success { color: #18732d; background: #eaf7ed; }
    .audit-badge.failure { color: #a1261c; background: #fff0ef; }
    .audit-badge.denied, .audit-badge.rate_limited { color: #805900; background: #fff7df; }
    .audit-detail-toggle { display: inline-flex; min-height: 2.75rem; align-items: center; padding: 0; border: 0; background: transparent; color: var(--accent); font: inherit; font-weight: 650; cursor: pointer; touch-action: manipulation; }
    .audit-detail-toggle:hover { text-decoration: underline; }
    .audit-detail-row[hidden] { display: none; }
    .audit-detail-row > td { padding: .25rem .5rem 1rem; }
    .audit-detail-list { display: grid; grid-template-columns: minmax(5rem, max-content) minmax(0, 1fr); gap: .55rem 1rem; width: 100%; margin: 0; padding: 1rem; border-radius: .85rem; background: var(--background); font-size: .82rem; }
    .audit-detail-list dt { color: var(--muted); font-weight: 650; }
    .audit-detail-list dd { min-width: 0; margin: 0; overflow-wrap: anywhere; word-break: break-word; }
    .audit-empty { padding: 3rem 1rem; color: var(--muted); text-align: center; }
    @media (max-width: 52rem) {
      .audit-filter-grid, .audit-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .audit-metric:nth-child(3) { border-left: 0; }
      .audit-metric:nth-child(n+3) { border-top: 1px solid var(--border); }
      .audit-table th:nth-child(5), .audit-event-row > td:nth-child(5) { display: none; }
    }
    @media (max-width: 30rem) {
      .shell { padding: 1.1rem 1rem; }
      main { padding: 2rem 0; }
      .panel { border-radius: 1.25rem; }
      .site-header { position: static; flex-wrap: wrap; }
      .account-nav { width: 100%; justify-content: flex-start; gap: .25rem; }
      .account-nav > a { padding-inline: .6rem; }
      .account-nav .button.compact { padding-inline: .65rem; }
      .section-heading > .button { width: 100%; }
      .audit-heading-tools { width: 100%; justify-content: flex-start; }
      .audit-filter-grid, .audit-summary { grid-template-columns: 1fr; }
      .audit-metric + .audit-metric { border-left: 0; border-top: 1px solid var(--border); }
      .audit-table th:nth-child(1), .audit-event-row > td:nth-child(1) { width: 7rem; }
      .audit-table th:nth-child(4), .audit-event-row > td:nth-child(4) { display: none; }
      .audit-detail-list { grid-template-columns: 4.5rem minmax(0, 1fr); gap: .5rem .75rem; padding: .85rem; }
    }
    @media (prefers-color-scheme: dark) {
      :root { color-scheme: dark; --background: #111113; --surface: #1c1c1e; --text: #f5f5f7; --muted: #b0b0b7; --border: #45454a; --accent: #64b5ff; --focus: #64b5ff; --message: #172b40; --error: #39201f; --toolbar: rgba(17, 17, 19, .9); }
      .panel { box-shadow: 0 1.25rem 3rem rgba(0, 0, 0, .18); }
      .button.primary { color: #fff; }
      .audit-badge.success { color: #7fdda0; background: #173622; }
      .audit-badge.failure { color: #ffaaa3; background: #40201e; }
      .audit-badge.denied, .audit-badge.rate_limited { color: #f2ca6e; background: #3a2e12; }
    }
    @media (prefers-contrast: more) {
      .panel, input:not([type="hidden"]), select, textarea, .button.secondary { border: 2px solid var(--text); }
      .lead, .hint, .switch, .site-label, .note-meta, .preview, .empty-content { color: var(--text); }
      .site-header { background: var(--background); backdrop-filter: none; -webkit-backdrop-filter: none; border-bottom: 2px solid var(--text); }
      .audit-badge { border: 1px solid currentColor; }
    }
    @media (prefers-reduced-transparency: reduce) {
      .site-header { background: var(--background); backdrop-filter: none; -webkit-backdrop-filter: none; }
    }
    @media (prefers-reduced-motion: reduce) {
      input:not([type="hidden"]), .button, .note-link { transition: none; }
      .button:active { transform: none; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="site-header">
      <a class="brand" href="{{ '/' if page == 'error' else url_for('index') }}">메모</a>
      {% if current_user and page != "error" %}
        <nav class="account-nav" aria-label="계정 메뉴">
          <a href="{{ url_for('list_notes') }}"{% if page in ['notes', 'note_form', 'note_detail', 'note_delete'] %} aria-current="{{ 'page' if page == 'notes' else 'true' }}"{% endif %}>내 메모</a>
          <a href="{{ url_for('change_password') }}"{% if page == 'password_change' and not admin_action %} aria-current="page"{% endif %}>비밀번호 변경</a>
          {% if current_user.is_admin %}<a href="{{ url_for('admin_users') }}"{% if page == 'admin' or (page == 'password_change' and admin_action) %} aria-current="{{ 'page' if page == 'admin' else 'true' }}"{% endif %}>회원 관리</a>{% endif %}
          {% if current_user.is_admin %}<a href="{{ url_for('admin_audit') }}"{% if page == 'audit' %} aria-current="page"{% endif %}>활동 기록</a>{% endif %}
          <form method="post" action="{{ url_for('logout') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <button class="button secondary compact" type="submit">로그아웃</button>
          </form>
        </nav>
      {% else %}
        <span class="site-label">나의 공간</span>
      {% endif %}
    </header>
    <main id="main-content"{% if page in ['notes', 'note_form', 'note_detail', 'admin', 'audit'] %} class="workspace"{% endif %}>
      <section class="panel{% if page in ['notes', 'note_form', 'note_detail', 'admin'] %} panel-wide{% elif page == 'audit' %} panel-audit{% endif %}" aria-labelledby="page-title">
        {% if page == "error" %}
          <p class="eyebrow">요청 안내</p>
          <h1 id="page-title">{{ title }}</h1>
          <p class="message error" role="alert">{{ error }}</p>
          <div class="actions"><a class="button secondary" href="/">홈으로 돌아가기</a></div>
        {% elif page == "notes" %}
          <div class="section-heading">
            <div>
              <p class="eyebrow">{{ current_user.username }}님의 공간</p>
              <h1 id="page-title">내 메모</h1>
              <p class="lead">나만 볼 수 있는 기록, {{ total }}개</p>
            </div>
            <a class="button primary" href="{{ url_for('create_note') }}">새 메모</a>
          </div>
          {% if notice %}<p class="message notice" role="status">{{ notice }}</p>{% endif %}
          {% if notes %}
            <ol class="note-list">
              {% for note in notes %}
                <li><a class="note-link" href="{{ url_for('view_note', note_id=note.id) }}">
                  <h2>{{ note.title }}</h2>
                  <p class="preview">{{ note.preview if note.preview.strip() else '내용 없는 메모' }}</p>
                  <span class="note-meta">수정 {{ note.updated_at|display_time }}</span>
                </a></li>
              {% endfor %}
            </ol>
          {% else %}
            <div class="empty-state"><h2>첫 생각을 남겨 보세요</h2><p class="lead">짧은 한 줄도 괜찮아요.<br>위의 새 메모에서 나만의 기록을 시작하세요.</p></div>
          {% endif %}
        {% elif page == "note_form" %}
          <p class="eyebrow">내 메모</p>
          <h1 id="page-title">{{ title }}</h1>
          {% if error %}<p class="message error" role="alert">{{ error }}</p>{% endif %}
          <form class="auth-form" method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <div class="field">
              <label for="note-title">제목</label>
              <input id="note-title" name="title" value="{{ form_title }}" required maxlength="{{ note_title_max_length }}">
            </div>
            <div class="field">
              <label for="note-content">내용</label>
              <textarea id="note-content" name="content" maxlength="{{ note_content_max_length }}" aria-describedby="content-hint">{{ form_content }}</textarea>
              <small id="content-hint" class="hint">내용은 비워 두거나 최대 {{ '{:,}'.format(note_content_max_length) }}자까지 저장할 수 있어요.</small>
            </div>
            <div class="inline-actions">
              <a class="button secondary" href="{{ cancel_url }}">취소</a>
              <button class="button primary" type="submit">저장</button>
            </div>
          </form>
        {% elif page == "note_detail" %}
          <p class="eyebrow">내 메모</p>
          <h1 id="page-title">{{ note.title }}</h1>
          <p class="note-meta">작성 {{ note.created_at|display_time }}<br>수정 {{ note.updated_at|display_time }}</p>
          {% if notice %}<p class="message notice" role="status">{{ notice }}</p>{% endif %}
          {% if note.content.strip() %}<div class="note-content">{{ note.content }}</div>
          {% else %}<p class="note-content empty-content">아직 내용이 없어요. 수정에서 내용을 더해 보세요.</p>{% endif %}
          <div class="inline-actions">
            <a class="button secondary" href="{{ url_for('list_notes') }}">목록</a>
            <a class="button primary" href="{{ url_for('edit_note', note_id=note.id) }}">수정</a>
            <a class="button secondary" href="{{ url_for('delete_note', note_id=note.id) }}">삭제</a>
          </div>
        {% elif page == "note_delete" %}
          <p class="eyebrow">메모 삭제</p>
          <h1 id="page-title">이 메모를 삭제할까요?</h1>
          <p class="lead">{{ note.title }}</p>
          <p class="hint">삭제한 메모는 복구할 수 없어요.</p>
          <form method="post" class="inline-actions">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <a class="button secondary" href="{{ url_for('view_note', note_id=note.id) }}">취소</a>
            <button class="button danger" type="submit">메모 삭제</button>
          </form>
        {% elif page == "admin" %}
          <p class="eyebrow">관리자</p>
          <h1 id="page-title">회원 관리</h1>
          <p class="lead">전체 회원 {{ total }}명</p>
          {% if notice %}<p class="message notice" role="status">{{ notice }}</p>{% endif %}
          <div class="table-wrap">
            <table aria-label="전체 회원 목록">
              <thead><tr><th scope="col">번호</th><th scope="col">아이디</th><th scope="col">역할</th><th scope="col">관리</th></tr></thead>
              <tbody>{% for member in members %}
                <tr><td>{{ member.id }}</td><td class="member-name">{{ member.username }}</td><td class="role-label">{{ '관리자' if member.is_admin else '회원' }}</td><td><a class="button secondary compact" href="{{ url_for('admin_change_password', user_id=member.id) }}" aria-label="{{ member.username }} 비밀번호 변경">비밀번호 변경</a></td></tr>
              {% endfor %}</tbody>
            </table>
          </div>
        {% elif page == "audit" %}
          <div class="section-heading">
            <div>
              <p class="eyebrow">관리자</p>
              <h1 id="page-title">활동 기록</h1>
              <p class="lead">최근 {{ retention_days }}일간 로그인과 주요 변경 이력을 확인합니다.</p>
            </div>
            <div class="audit-heading-tools">
              <span id="audit-status" class="audit-status" data-state="{{ 'live' if poll_url else 'paused' }}" role="status" aria-live="polite">{{ '자동 갱신 중' if poll_url else '과거 기록 보기' }}</span>
              {% if poll_url %}<button id="audit-pause" class="button secondary compact" type="button" aria-pressed="false">일시정지</button>{% endif %}
              <button id="audit-refresh" class="button secondary compact" type="button">새로고침</button>
            </div>
          </div>
          <dl class="audit-summary" aria-label="최근 24시간 요약">
            <div class="audit-metric"><dt>로그인 성공</dt><dd id="metric-login-success">{{ summary.login_success }}</dd></div>
            <div class="audit-metric"><dt>로그인 실패·제한</dt><dd id="metric-login-failure">{{ summary.login_failure }}</dd></div>
            <div class="audit-metric"><dt>활동 사용자</dt><dd id="metric-active-users">{{ summary.active_users }}</dd></div>
            <div class="audit-metric"><dt>권한 거부</dt><dd id="metric-denied">{{ summary.denied }}</dd></div>
          </dl>
          <form class="audit-filters" method="get" action="{{ url_for('admin_audit') }}">
            <div class="audit-filter-grid">
              <div><label for="audit-period">기간</label><select id="audit-period" name="period">{% for value, label in filter_labels.period.items() %}<option value="{{ value }}"{% if filters.period == value %} selected{% endif %}>{{ label }}</option>{% endfor %}</select></div>
              <div><label for="audit-outcome">결과</label><select id="audit-outcome" name="outcome">{% for value, label in filter_labels.outcome.items() %}<option value="{{ value }}"{% if filters.outcome == value %} selected{% endif %}>{{ label }}</option>{% endfor %}</select></div>
              <div><label for="audit-category">행동</label><select id="audit-category" name="category">{% for value, label in filter_labels.category.items() %}<option value="{{ value }}"{% if filters.category == value %} selected{% endif %}>{{ label }}</option>{% endfor %}</select></div>
              <div><label for="audit-username">사용자</label><input id="audit-username" name="username" value="{{ filters.username }}" maxlength="30" placeholder="아이디 정확히 입력" autocomplete="off"></div>
              <div><label for="audit-ip">IP 주소</label><input id="audit-ip" name="ip" value="{{ filters.ip }}" maxlength="45" placeholder="예: 203.0.113.10" inputmode="text" autocomplete="off" dir="ltr"></div>
            </div>
            <div class="audit-filter-actions">
              <button class="button primary compact" type="submit">필터 적용</button>
              <a class="button secondary compact" href="{{ url_for('admin_audit') }}">초기화</a>
              <span class="hint" id="audit-total" data-total="{{ total }}">총 {{ total }}건</span>
            </div>
          </form>
          <div class="table-wrap">
            <table class="audit-table">
              <caption class="sr-only">필터된 활동 기록, 최신순</caption>
              <thead><tr><th scope="col">시각</th><th scope="col">결과</th><th scope="col">행동</th><th scope="col">사용자</th><th scope="col">IP</th><th scope="col">상세</th></tr></thead>
              <tbody id="audit-events" data-poll-url="{{ poll_url or '' }}" data-latest-id="{{ latest_id }}">
                {% for event in events %}
                  <tr class="audit-event-row" data-event-id="{{ event.id }}" data-detail-id="audit-detail-{{ event.id }}">
                    <td><time class="audit-time" datetime="{{ event.created_at }}">{{ event.display_time }}</time></td>
                    <td><span class="audit-badge {{ event.outcome }}">{{ event.outcome_label }}</span></td>
                    <td>{{ event.event_label }}<span class="audit-secondary">{{ event.channel }} · {{ event.target }}</span></td>
                    <td>{{ event.actor }}</td>
                    <td class="audit-ip" dir="ltr" translate="no">{{ event.source_ip }}</td>
                    <td><button class="audit-detail-toggle" type="button" aria-expanded="false" aria-controls="audit-detail-{{ event.id }}">보기</button></td>
                  </tr>
                  <tr id="audit-detail-{{ event.id }}" class="audit-detail-row" hidden><td colspan="6"><dl class="audit-detail-list">
                    <dt>대상</dt><dd>{{ event.target }}</dd><dt>경로</dt><dd>{{ event.channel }}</dd><dt>사유</dt><dd>{{ event.reason }}</dd>
                    <dt>IP</dt><dd dir="ltr" translate="no">{{ event.source_ip }}</dd><dt>User-Agent</dt><dd>{{ event.user_agent }}</dd>
                    <dt>요청 ID</dt><dd dir="ltr" translate="no">{{ event.request_id }}</dd>
                  </dl></td></tr>
                {% endfor %}
                {% if not events %}<tr id="audit-empty"><td class="audit-empty" colspan="6">조건에 맞는 활동 기록이 없습니다.</td></tr>{% endif %}
              </tbody>
            </table>
          </div>
          {% if pages > 1 %}<nav class="pagination" aria-label="활동 기록 페이지 이동">
            {% if previous_url %}<a class="button secondary compact" href="{{ previous_url }}">이전</a>{% else %}<span></span>{% endif %}
            <span class="hint" aria-current="page">{{ number }} / {{ pages }} 페이지</span>
            {% if next_url %}<a class="button secondary compact" href="{{ next_url }}">다음</a>{% else %}<span></span>{% endif %}
          </nav>{% endif %}
        {% elif page == "password_change" %}
          <p class="eyebrow">{{ '회원 관리' if admin_action else '내 계정' }}</p>
          <h1 id="page-title">{{ title }}</h1>
          <p class="lead">{{ member.username }} 계정의 비밀번호를 변경합니다.</p>
          <p class="hint" id="session-hint">변경하면 해당 계정의 모든 기기에서 로그아웃됩니다. 새 비밀번호로 다시 로그인해 주세요.</p>
          {% if error %}<p class="message error" role="alert">{{ error }}</p>{% endif %}
          <form class="auth-form" method="post" aria-describedby="session-hint">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <div class="field">
              <label for="current-password">{{ '관리자 본인의 현재 비밀번호' if admin_action else '현재 비밀번호' }}</label>
              <input id="current-password" type="password" name="current_password" autocomplete="current-password" required maxlength="{{ password_max_length }}">
            </div>
            <div class="field">
              <label for="new-password">새 비밀번호</label>
              <input id="new-password" type="password" name="new_password" autocomplete="new-password" required minlength="{{ password_min_length }}" maxlength="{{ password_max_length }}" aria-describedby="password-hint">
              <small class="hint" id="password-hint">{{ password_min_length }}~{{ password_max_length }}자. 여러 단어를 조합해 보세요.</small>
            </div>
            <div class="field">
              <label for="confirm-password">새 비밀번호 확인</label>
              <input id="confirm-password" type="password" name="confirm_password" autocomplete="new-password" required minlength="{{ password_min_length }}" maxlength="{{ password_max_length }}">
            </div>
            <div class="inline-actions">
              <a class="button secondary" href="{{ url_for('admin_users' if admin_action else 'list_notes') }}">취소</a>
              <button class="button primary" type="submit">비밀번호 변경</button>
            </div>
          </form>
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
        {% if page in ['notes', 'admin'] and pages > 1 %}
          <nav class="pagination" aria-label="페이지 이동">
            {% if number > 1 %}<a class="button secondary compact" href="{{ url_for('admin_users' if page == 'admin' else 'list_notes', page=number-1) }}">이전</a>{% else %}<span></span>{% endif %}
            <span class="hint" aria-current="page">{{ number }} / {{ pages }} 페이지</span>
            {% if number < pages %}<a class="button secondary compact" href="{{ url_for('admin_users' if page == 'admin' else 'list_notes', page=number+1) }}">다음</a>{% else %}<span></span>{% endif %}
          </nav>
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


def backup_database(db, db_path, label):
    if db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None:
        return
    backup_path = db_path.with_name(f"{db_path.name}.{label}-{secrets.token_hex(8)}.db")
    descriptor = os.open(backup_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    # Use a separate read connection: backing up the connection holding the
    # migration's write reservation would wait for its own transaction.
    with closing(sqlite3.connect(db_path)) as source, closing(sqlite3.connect(backup_path)) as backup:
        source.backup(backup)


def migrate_database(db, db_path):
    version = db.execute("PRAGMA user_version").fetchone()[0]
    starting_version = version
    if version > 2:
        raise RuntimeError("The database schema is newer than this application supports.")
    if version == 0:
        backup_database(db, db_path, "before-api-v1")
        db.execute("""
            CREATE TABLE notes_api_v1 (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
                content TEXT NOT NULL CHECK (length(content) BETWEEN 0 AND 10000),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
        db.execute("INSERT INTO notes_api_v1 SELECT id, user_id, title, content, created_at, updated_at FROM notes")
        db.execute("DROP TABLE notes")
        db.execute("ALTER TABLE notes_api_v1 RENAME TO notes")
        db.execute("CREATE INDEX notes_owner_updated ON notes(user_id, updated_at DESC, id DESC)")
        db.execute("PRAGMA user_version = 1")
        version = 1
    if version == 1:
        if starting_version == 1:
            backup_database(db, db_path, "before-audit-v2")
        db.execute("""
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY,
                created_at INTEGER NOT NULL,
                event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 50),
                outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'rate_limited')),
                actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                actor_username TEXT CHECK (actor_username IS NULL OR length(actor_username) <= 30),
                attempted_username TEXT CHECK (attempted_username IS NULL OR length(attempted_username) <= 30),
                target_type TEXT CHECK (target_type IS NULL OR length(target_type) <= 30),
                target_id INTEGER,
                target_label TEXT CHECK (target_label IS NULL OR length(target_label) <= 120),
                source_ip TEXT NOT NULL CHECK (length(source_ip) BETWEEN 1 AND 45),
                user_agent TEXT NOT NULL CHECK (length(user_agent) <= 300),
                channel TEXT NOT NULL CHECK (channel IN ('web', 'api')),
                reason_code TEXT CHECK (reason_code IS NULL OR length(reason_code) <= 40),
                request_id TEXT NOT NULL CHECK (length(request_id) = 32)
            )
        """)
        db.execute("CREATE INDEX audit_events_created ON audit_events(created_at DESC, id DESC)")
        db.execute("CREATE INDEX audit_events_type_created ON audit_events(event_type, created_at DESC)")
        db.execute("CREATE INDEX audit_events_outcome_created ON audit_events(outcome, created_at DESC)")
        db.execute("CREATE INDEX audit_events_actor_created ON audit_events(actor_user_id, created_at DESC)")
        db.execute("CREATE INDEX audit_events_actor_name_created ON audit_events(actor_username, created_at DESC)")
        db.execute("CREATE INDEX audit_events_attempted_name_created ON audit_events(attempted_username, created_at DESC)")
        db.execute("CREATE INDEX audit_events_ip_created ON audit_events(source_ip, created_at DESC)")
        db.execute("PRAGMA user_version = 2")


def init_db():
    db_path = Path(app.config["DATABASE"])
    descriptor = os.open(db_path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(descriptor)
    db_path.chmod(0o600)
    with app.app_context():
        db = get_db()
        if db.execute("PRAGMA user_version").fetchone()[0] > 2:
            raise RuntimeError("The database schema is newer than this application supports.")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1))
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
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
                content TEXT NOT NULL CHECK (length(content) BETWEEN 0 AND 10000),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS notes_owner_updated ON notes(user_id, updated_at DESC, id DESC);
        """)
        with db:
            # Serialize schema migration and bootstrap across application workers.
            db.execute("BEGIN IMMEDIATE")
            migrate_database(db, db_path)
            columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
            if "is_admin" not in columns:
                db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1))")
            admin = db.execute("SELECT id, is_admin FROM users WHERE username = ?", ("admin",)).fetchone()
            if admin is not None:
                if not admin["is_admin"]:
                    raise RuntimeError("An existing non-admin account uses the reserved admin name. Resolve the conflict before initialization.")
                return
            admin_password = os.environ.get("ADMIN_PASSWORD", "")
            if not PASSWORD_MIN_LENGTH <= len(admin_password) <= PASSWORD_MAX_LENGTH:
                raise RuntimeError("First launch requires ADMIN_PASSWORD with 15-128 characters.")
            admin_note = os.environ.get("ADMIN_NOTE") or f"SBOB{{daewon_{secrets.token_hex(12)}}}"
            if re.fullmatch(r"SBOB\{[A-Za-z0-9_.:-]{1,100}\}", admin_note) is None:
                raise RuntimeError("ADMIN_NOTE must have the form SBOB{your_identifier}.")
            admin_id = db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                ("admin", generate_password_hash(admin_password)),
            ).lastrowid
            now = int(time.time())
            db.execute(
                "INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (admin_id, "관리자 개인 메모", admin_note, now, now),
            )


def token_digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


AUDIT_EVENT_LABELS = {
    "auth.login": "로그인",
    "auth.logout": "로그아웃",
    "account.register": "회원가입",
    "account.password_change": "비밀번호 변경",
    "admin.member_password_change": "회원 비밀번호 변경",
    "authorization.admin_denied": "관리자 접근 거부",
    "note.create": "메모 생성",
    "note.update": "메모 수정",
    "note.delete": "메모 삭제",
}
AUDIT_OUTCOME_LABELS = {
    "success": "성공", "failure": "실패", "denied": "거부", "rate_limited": "제한",
}


def maybe_cleanup_audit_events(db, now):
    global audit_cleanup_deadline
    monotonic_now = time.monotonic()
    if monotonic_now < audit_cleanup_deadline:
        return
    with audit_cleanup_lock:
        if monotonic_now < audit_cleanup_deadline:
            return
        cutoff = now - app.config["AUDIT_RETENTION_DAYS"] * 86400
        db.execute(
            "DELETE FROM audit_events WHERE id IN "
            "(SELECT id FROM audit_events WHERE created_at < ? ORDER BY created_at LIMIT 1000)",
            (cutoff,),
        )
        audit_cleanup_deadline = monotonic_now + 3600


def clean_audit_text(value, limit):
    if not value:
        return None
    cleaned = "".join("�" if unicodedata.category(char).startswith("C") else char for char in str(value))
    return cleaned[:limit]


def insert_audit_event(
    db, event_type, outcome, *, actor_user_id=None, actor_username=None,
    attempted_username=None, target_type=None, target_id=None, target_label=None,
    reason_code=None, channel=None,
):
    if event_type not in AUDIT_EVENT_TYPES or outcome not in AUDIT_OUTCOMES:
        raise ValueError("Unknown audit event.")
    if reason_code not in AUDIT_REASON_CODES:
        raise ValueError("Unknown audit reason.")
    if channel is None:
        channel = "api" if getattr(g, "is_api", False) else "web"
    if channel not in AUDIT_CHANNELS:
        raise ValueError("Unknown audit channel.")
    actor = getattr(g, "user", None)
    if actor is not None:
        actor_user_id = actor_user_id if actor_user_id is not None else actor["id"]
        actor_username = actor_username if actor_username is not None else actor["username"]
    request_id = getattr(g, "request_id", "")
    if REQUEST_ID_PATTERN.fullmatch(request_id) is None:
        raise RuntimeError("Request ID is unavailable.")
    now = int(time.time())
    maybe_cleanup_audit_events(db, now)
    return db.execute(
        "INSERT INTO audit_events "
        "(created_at, event_type, outcome, actor_user_id, actor_username, attempted_username, "
        "target_type, target_id, target_label, source_ip, user_agent, channel, reason_code, request_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            now, event_type, outcome, actor_user_id,
            clean_audit_text(actor_username, 30), clean_audit_text(attempted_username, 30),
            clean_audit_text(target_type, 30), target_id, clean_audit_text(target_label, 120),
            (request.remote_addr or "unknown")[:45], clean_audit_text(request.user_agent.string, 300) or "",
            channel, reason_code, request_id,
        ),
    ).lastrowid


def record_audit_event(event_type, outcome, **context):
    db = get_db()
    with db:
        return insert_audit_event(db, event_type, outcome, **context)


def record_admin_denial():
    db = get_db()
    now = int(time.time())
    scope = f"admin-denied:{g.user['id']}:{request.endpoint}:{request.remote_addr or 'unknown'}"
    key = hashlib.sha256(scope.encode("utf-8")).hexdigest()
    with db:
        db.execute("DELETE FROM auth_limits WHERE resets_at <= ?", (now,))
        created = db.execute(
            "INSERT INTO auth_limits (key, attempts, resets_at) VALUES (?, 1, ?) "
            "ON CONFLICT(key) DO NOTHING",
            (key, now + 300),
        )
        if created.rowcount == 1:
            insert_audit_event(
                db, "authorization.admin_denied", "denied",
                target_type="endpoint", target_label=request.endpoint,
                reason_code="admin_required",
            )


def enforce_auth_limit(*, account_id=None, audit_context=None):
    limit, window = AUTH_LIMITS[request.endpoint]
    # Use the actual peer address. Forwarded headers are not trusted by default.
    source = f"{request.endpoint}:{request.remote_addr or 'unknown'}"
    if account_id is not None:
        # Both password-change screens share a limit for the acting account.
        scope = "password-change" if request.endpoint in {"change_password", "admin_change_password"} else request.endpoint
        source = f"{scope}:account:{account_id}"
    key = hashlib.sha256(source.encode("utf-8")).hexdigest()
    now = int(time.time())
    db = get_db()
    # SQLite serializes this write transaction, including across WSGI workers.
    with db:
        db.execute("DELETE FROM auth_limits WHERE resets_at <= ?", (now,))
        db.execute(
            "INSERT INTO auth_limits (key, attempts, resets_at) VALUES (?, 1, ?) "
            "ON CONFLICT(key) DO UPDATE SET attempts = MIN(auth_limits.attempts + 1, ?)",
            (key, now + window, limit + 2),
        )
        entry = db.execute("SELECT attempts, resets_at FROM auth_limits WHERE key = ?", (key,)).fetchone()
        if entry["attempts"] == limit + 1:
            event_type = {
                "login": "auth.login", "register": "account.register",
                "change_password": "account.password_change",
                "admin_change_password": "admin.member_password_change",
                "api_create_note": "note.create",
            }[request.endpoint]
            insert_audit_event(
                db, event_type, "rate_limited",
                attempted_username=request.form.get("username") if request.endpoint in {"login", "register"} else None,
                reason_code="rate_limit",
                **(audit_context or {}),
            )
    if entry["attempts"] > limit:
        raise TooManyRequests(retry_after=max(1, entry["resets_at"] - now))


@app.before_request
def prepare_request():
    g.csp_nonce = secrets.token_urlsafe(24)
    g.request_id = secrets.token_hex(16)
    g.user = None
    g.is_api = request.path.startswith("/api/")
    if request.routing_exception is not None and (
        not g.is_api or getattr(request.routing_exception, "code", None) not in {404, 405, 308}
    ):
        return
    if app.config["PRODUCTION"] and not request.is_secure:
        abort(400)
    if g.is_api:
        load_current_user()
        if g.user is None:
            abort(401)
        if request.routing_exception is not None:
            if request.routing_exception.code == 308:
                abort(404)
            return
        if request.method == "POST":
            if request.mimetype != "application/json":
                abort(415)
            check_csrf(request.headers.get("X-CSRF-Token", ""))
            enforce_auth_limit(account_id=g.user["id"])
        return
    if request.method == "POST":
        if request.endpoint not in {"create_note", "edit_note"}:
            request.max_content_length = 16 * 1024
        if request.mimetype != "application/x-www-form-urlencoded":
            abort(415)
        fields = POST_FIELDS.get(request.endpoint)
        if fields is None:
            abort(405)
        if set(request.form) != fields or any(len(request.form.getlist(field)) != 1 for field in fields):
            abort(400)
        check_csrf()
        if request.endpoint in {"login", "register"}:
            enforce_auth_limit()
    load_current_user()


def load_current_user():
    token = session.get("auth_token")
    if token is None:
        return
    if not isinstance(token, str) or TOKEN_PATTERN.fullmatch(token) is None:
        session.clear()
        return
    db = get_db()
    digest = token_digest(token)
    g.user = db.execute(
        "SELECT users.id, users.username, users.is_admin FROM auth_sessions "
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
        f"default-src 'none'; style-src 'nonce-{nonce}'; script-src 'self'; connect-src 'self'; img-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["X-Request-ID"] = getattr(g, "request_id", "")
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
        401: "로그인이 필요합니다.",
        403: "이 페이지에 접근할 권한이 없습니다.",
        404: "요청한 페이지를 찾을 수 없습니다.",
        405: "지원하지 않는 요청 방식입니다.",
        409: "계정 정보가 변경되었습니다. 페이지를 새로 열고 다시 시도해 주세요.",
        413: "입력한 데이터가 너무 큽니다.",
        415: "화면의 입력 양식을 사용해 주세요.",
        429: "요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.",
        500: "요청을 처리하지 못했습니다. 잠시 후 다시 시도해 주세요.",
    }
    response = error.get_response()
    if request.path.startswith("/api/"):
        message = messages.get(error.code, messages[400])
        if error.code == 415:
            message = "Content-Type: application/json으로 요청하세요."
        response.set_data(app.json.dumps({"error": message}))
        response.content_type = "application/json"
        return response
    html, _ = page("error", "요청을 처리할 수 없어요", error=messages.get(error.code, messages[400]), status=error.code)
    response.set_data(html)
    response.content_type = "text/html; charset=utf-8"
    return response


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def check_csrf(supplied=None):
    if supplied is None:
        supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if (
        TOKEN_PATTERN.fullmatch(supplied) is None
        or not isinstance(expected, str)
        or TOKEN_PATTERN.fullmatch(expected) is None
        or not secrets.compare_digest(supplied, expected)
    ):
        abort(400)


def page(name, title, *, username=None, error=None, notice=None, status=200, **context):
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
            current_user=g.user,
            note_title_max_length=NOTE_TITLE_MAX_LENGTH,
            note_content_max_length=NOTE_CONTENT_MAX_LENGTH,
            **context,
        ),
        status,
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        if not g.user["is_admin"]:
            record_admin_denial()
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def owned_note(note_id):
    if not 1 <= note_id <= 2**63 - 1:
        abort(404)
    note = get_db().execute(
        "SELECT id, title, content, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?",
        (note_id, g.user["id"]),
    ).fetchone()
    if note is None:
        abort(404)
    return note


def pagination(total):
    values = request.args.getlist("page") or ["1"]
    if len(values) != 1 or re.fullmatch(r"[1-9][0-9]{0,8}", values[0]) is None:
        abort(400)
    number = int(values[0])
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if number > pages:
        abort(404)
    return number, pages


AUDIT_PERIODS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "all": None}
AUDIT_CATEGORIES = {
    "all": (),
    "auth": ("auth.login", "auth.logout"),
    "account": ("account.register", "account.password_change"),
    "note": ("note.create", "note.update", "note.delete"),
    "admin": ("admin.member_password_change", "authorization.admin_denied"),
}
AUDIT_FILTER_LABELS = {
    "period": {"24h": "최근 24시간", "7d": "최근 7일", "30d": "최근 30일", "all": "전체 보존 기간"},
    "outcome": {"all": "모든 결과", "success": "성공", "failure": "실패", "denied": "거부·제한"},
    "category": {"all": "모든 행동", "auth": "로그인·로그아웃", "account": "계정", "note": "메모", "admin": "관리자"},
}
AUDIT_REASON_LABELS = {
    None: "-", "invalid_input": "입력 형식 오류", "invalid_credentials": "인증 정보 불일치",
    "username_conflict": "아이디 중복", "current_password_mismatch": "현재 비밀번호 불일치",
    "confirmation_mismatch": "비밀번호 확인 불일치", "password_reused": "기존 비밀번호 재사용",
    "concurrent_change": "처리 중 계정 정보 변경", "rate_limit": "요청 횟수 제한",
    "admin_required": "관리자 권한 필요",
}


def read_audit_filters(*, polling=False):
    allowed = {"period", "outcome", "category", "username", "ip", "after_id" if polling else "page"}
    if set(request.args) - allowed or any(len(request.args.getlist(key)) != 1 for key in request.args):
        abort(400)
    filters = {
        "period": request.args.get("period", "24h"),
        "outcome": request.args.get("outcome", "all"),
        "category": request.args.get("category", "all"),
        "username": request.args.get("username", "").strip(),
        "ip": request.args.get("ip", "").strip(),
    }
    if filters["period"] not in AUDIT_PERIODS or filters["outcome"] not in AUDIT_FILTER_LABELS["outcome"]:
        abort(400)
    if filters["category"] not in AUDIT_CATEGORIES:
        abort(400)
    if filters["username"] and (
        len(filters["username"]) > 30 or any(ord(char) < 32 or ord(char) == 127 for char in filters["username"])
    ):
        abort(400)
    if filters["ip"]:
        try:
            filters["ip"] = str(ipaddress.ip_address(filters["ip"]))
        except ValueError:
            abort(400)
    number = None
    after_id = None
    if polling:
        value = request.args.get("after_id", "0")
        if re.fullmatch(r"0|[1-9][0-9]{0,18}", value) is None or int(value) > 2**63 - 1:
            abort(400)
        after_id = int(value)
    else:
        value = request.args.get("page", "1")
        if re.fullmatch(r"[1-9][0-9]{0,8}", value) is None:
            abort(400)
        number = int(value)
    return filters, number, after_id


def audit_where(filters, *, after_id=None):
    clauses, values = [], []
    seconds = AUDIT_PERIODS[filters["period"]]
    if seconds is not None:
        clauses.append("created_at >= ?")
        values.append(int(time.time()) - seconds)
    if filters["outcome"] == "success":
        clauses.append("outcome = 'success'")
    elif filters["outcome"] == "failure":
        clauses.append("outcome = 'failure'")
    elif filters["outcome"] == "denied":
        clauses.append("outcome IN ('denied', 'rate_limited')")
    event_types = AUDIT_CATEGORIES[filters["category"]]
    if event_types:
        clauses.append(f"event_type IN ({','.join('?' for _ in event_types)})")
        values.extend(event_types)
    if filters["username"]:
        clauses.append("(actor_username = ? OR attempted_username = ?)")
        values.extend((filters["username"], filters["username"]))
    if filters["ip"]:
        clauses.append("source_ip = ?")
        values.append(filters["ip"])
    if after_id is not None:
        clauses.append("id > ?")
        values.append(after_id)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", values


def audit_summary(db):
    since = int(time.time()) - 86400
    row = db.execute(
        "SELECT "
        "SUM(event_type = 'auth.login' AND outcome = 'success') AS login_success, "
        "SUM(event_type = 'auth.login' AND outcome IN ('failure', 'rate_limited')) AS login_failure, "
        "COUNT(DISTINCT CASE WHEN outcome = 'success' THEN actor_user_id END) AS active_users, "
        "SUM(outcome = 'denied') AS denied "
        "FROM audit_events WHERE created_at >= ?",
        (since,),
    ).fetchone()
    return {key: int(row[key] or 0) for key in ("login_success", "login_failure", "active_users", "denied")}


def audit_event_json(event):
    actor = event["actor_username"] or event["attempted_username"] or "알 수 없음"
    target = event["target_label"]
    if target is None and event["target_type"] and event["target_id"] is not None:
        target = f"{event['target_type']} #{event['target_id']}"
    return {
        "id": event["id"],
        "created_at": datetime.fromtimestamp(event["created_at"], NOTE_TIMEZONE).isoformat(),
        "display_time": display_time(event["created_at"]),
        "event_type": event["event_type"],
        "event_label": AUDIT_EVENT_LABELS[event["event_type"]],
        "outcome": event["outcome"],
        "outcome_label": AUDIT_OUTCOME_LABELS[event["outcome"]],
        "actor": actor,
        "target": target or "-",
        "source_ip": event["source_ip"],
        "user_agent": event["user_agent"] or "-",
        "channel": "API" if event["channel"] == "api" else "웹",
        "reason": AUDIT_REASON_LABELS[event["reason_code"]],
        "request_id": event["request_id"],
    }


def validate_note(title, content):
    try:
        title.encode("utf-8")
        content.encode("utf-8")
    except UnicodeEncodeError:
        return "올바른 유니코드 문자를 입력해 주세요."
    if not 1 <= len(title) <= NOTE_TITLE_MAX_LENGTH or any(ord(char) < 32 or ord(char) == 127 for char in title):
        return f"제목은 줄바꿈 없이 1~{NOTE_TITLE_MAX_LENGTH}자로 입력해 주세요."
    if len(content) > NOTE_CONTENT_MAX_LENGTH:
        return f"내용은 {NOTE_CONTENT_MAX_LENGTH:,}자까지 입력할 수 있어요."
    if any(ord(char) < 32 and char not in "\r\n\t" for char in content):
        return "내용에 사용할 수 없는 제어 문자가 포함되어 있어요."
    return None


def read_note_form():
    title = request.form["title"].strip()
    content = request.form["content"]
    return title, content, validate_note(title, content)


@app.template_filter("display_time")
def display_time(timestamp):
    return datetime.fromtimestamp(timestamp, NOTE_TIMEZONE).strftime("%Y.%m.%d %H:%M KST")


def note_json(note):
    return {
        "id": note["id"],
        "title": note["title"],
        "body": note["content"],
        "created_at": datetime.fromtimestamp(note["created_at"], NOTE_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": datetime.fromtimestamp(note["updated_at"], NOTE_TIMEZONE).strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get("/api/csrf")
def api_csrf():
    return jsonify(csrf_token=csrf_token())


@app.get("/api/notes")
def api_list_notes():
    notes = get_db().execute(
        "SELECT id, title, content, created_at, updated_at FROM notes "
        "WHERE user_id = ? ORDER BY updated_at DESC, id DESC", (g.user["id"],)
    ).fetchall()
    return jsonify(notes=[note_json(note) for note in notes])


@app.post("/api/notes")
def api_create_note():
    try:
        data = request.get_json()
    except RecursionError:
        abort(400)
    if not isinstance(data, dict) or set(data) - {"title", "body"}:
        abort(400)
    if not isinstance(data.get("title"), str) or not isinstance(data.get("body", ""), str):
        abort(400)
    title, content = data["title"].strip(), data.get("body", "")
    error = validate_note(title, content)
    if error:
        return jsonify(error=error), 400
    now = int(time.time())
    db = get_db()
    with db:
        note_id = db.execute(
            "INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (g.user["id"], title, content, now, now),
        ).lastrowid
        insert_audit_event(
            db, "note.create", "success", target_type="note", target_id=note_id, channel="api",
        )
    response = jsonify(note_json(owned_note(note_id)))
    response.status_code = 201
    response.headers["Location"] = url_for("api_view_note", note_id=note_id)
    return response


@app.get("/api/notes/<int:note_id>")
def api_view_note(note_id):
    return jsonify(note_json(owned_note(note_id)))


@app.route("/")
def index():
    if g.user is not None:
        return redirect(url_for("list_notes"))
    return page("home", "홈", username=g.user["username"] if g.user else None)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user is not None:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username.casefold() == "admin":
            record_audit_event("account.register", "failure", attempted_username=username, reason_code="invalid_input")
            return page("register", "회원가입", error="사용할 수 없는 아이디입니다.", status=400)
        if not 3 <= len(username) <= 30 or not all(char.isalnum() or char in "_.-" for char in username):
            record_audit_event("account.register", "failure", attempted_username=username, reason_code="invalid_input")
            return page("register", "회원가입", error="아이디는 3~30자의 글자, 숫자, 밑줄, 점, 하이픈으로 입력하세요.", status=400)
        if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
            record_audit_event("account.register", "failure", attempted_username=username, reason_code="invalid_input")
            return page("register", "회원가입", error=f"비밀번호는 {PASSWORD_MIN_LENGTH}~{PASSWORD_MAX_LENGTH}자로 입력하세요.", status=400)
        db = get_db()
        conflict = False
        with db:
            result = db.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0) "
                "ON CONFLICT(username) DO NOTHING",
                (username, generate_password_hash(password)),
            )
            if result.rowcount != 1:
                conflict = True
            else:
                user_id = result.lastrowid
                insert_audit_event(
                    db, "account.register", "success", actor_user_id=user_id,
                    actor_username=username, attempted_username=username,
                    target_type="user", target_id=user_id, target_label=username,
                )
        if conflict:
            record_audit_event(
                "account.register", "failure", attempted_username=username,
                target_type="user", target_label=username, reason_code="username_conflict",
            )
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
            record_audit_event("auth.login", "failure", attempted_username=username, reason_code="invalid_credentials")
            return page("login", "로그인", error=invalid_login, status=401)
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        password_matches = check_password_hash(user["password_hash"] if user else DUMMY_PASSWORD_HASH, password)
        if user is None or not password_matches:
            record_audit_event("auth.login", "failure", attempted_username=username, reason_code="invalid_credentials")
            return page("login", "로그인", error=invalid_login, status=401)
        token = secrets.token_hex(32)
        now = int(time.time())
        expires_at = now + int(app.permanent_session_lifetime.total_seconds())
        db = get_db()
        with db:
            db.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))
            # A concurrent password change must not issue a session for the old hash.
            result = db.execute(
                "INSERT INTO auth_sessions (token_hash, user_id, expires_at) "
                "SELECT ?, id, ? FROM users WHERE id = ? AND password_hash = ?",
                (token_digest(token), expires_at, user["id"], user["password_hash"]),
            )
            if result.rowcount != 1:
                insert_audit_event(
                    db, "auth.login", "failure", attempted_username=username,
                    reason_code="concurrent_change",
                )
                return page("login", "로그인", error=invalid_login, status=401)
            insert_audit_event(
                db, "auth.login", "success", actor_user_id=user["id"],
                actor_username=user["username"], attempted_username=username,
                target_type="user", target_id=user["id"], target_label=user["username"],
            )
        session.clear()
        session["auth_token"] = token
        session.permanent = True
        return redirect(url_for("index"))
    notice = None
    if request.args.get("password_changed") == "1":
        notice = "비밀번호가 변경되어 모든 기기에서 로그아웃되었습니다. 새 비밀번호로 로그인하세요."
    elif request.args.get("registered") == "1":
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
            if g.user is not None:
                insert_audit_event(
                    db, "auth.logout", "success",
                    target_type="user", target_id=g.user["id"], target_label=g.user["username"],
                )
    session.clear()
    return redirect(url_for("login", logged_out=1))


def password_change_form(member, *, admin_action=False):
    error, status, reason_code = None, 200, None
    event_type = "admin.member_password_change" if admin_action else "account.password_change"
    audit_target = {
        "target_type": "user", "target_id": member["id"], "target_label": member["username"],
    }
    if request.method == "POST":
        enforce_auth_limit(account_id=g.user["id"], audit_context=audit_target)
        current = request.form["current_password"]
        new = request.form["new_password"]
        confirmation = request.form["confirm_password"]
        db = get_db()
        actor = db.execute("SELECT password_hash FROM users WHERE id = ?", (g.user["id"],)).fetchone()
        if not PASSWORD_MIN_LENGTH <= len(new) <= PASSWORD_MAX_LENGTH:
            error, status, reason_code = f"새 비밀번호는 {PASSWORD_MIN_LENGTH}~{PASSWORD_MAX_LENGTH}자로 입력하세요.", 400, "invalid_input"
        elif new != confirmation:
            error, status, reason_code = "새 비밀번호와 확인 입력이 일치하지 않습니다.", 400, "confirmation_mismatch"
        elif not 1 <= len(current) <= PASSWORD_MAX_LENGTH or actor is None or not check_password_hash(actor["password_hash"], current):
            error, status, reason_code = "현재 비밀번호가 올바르지 않습니다.", 401, "current_password_mismatch"
        elif check_password_hash(member["password_hash"], new):
            error, status, reason_code = "기존 비밀번호와 다른 새 비밀번호를 입력하세요.", 400, "password_reused"
        else:
            new_hash = generate_password_hash(new)
            authorization_failed = False
            with db:
                db.execute("BEGIN IMMEDIATE")
                # Recheck authority inside the write transaction, including revocation
                # or password/role changes while password hashing was in progress.
                authorized = db.execute(
                    "SELECT 1 FROM users JOIN auth_sessions ON auth_sessions.user_id = users.id "
                    "WHERE users.id = ? AND users.password_hash = ? "
                    "AND auth_sessions.token_hash = ? AND auth_sessions.expires_at > ? "
                    "AND (? = 0 OR users.is_admin = 1)",
                    (g.user["id"], actor["password_hash"], token_digest(session["auth_token"]),
                     int(time.time()), int(admin_action)),
                ).fetchone()
                if authorized is None:
                    authorization_failed = True
                else:
                    result = db.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
                        (new_hash, member["id"], member["password_hash"]),
                    )
                    if result.rowcount != 1:
                        abort(409)
                    db.execute("DELETE FROM auth_sessions WHERE user_id = ?", (member["id"],))
                    insert_audit_event(db, event_type, "success", **audit_target)
            if authorization_failed:
                record_audit_event(event_type, "denied", reason_code="concurrent_change", **audit_target)
                abort(403)
            if member["id"] == g.user["id"]:
                session.clear()
                return redirect(url_for("login", password_changed=1))
            session["csrf_token"] = secrets.token_hex(32)
            return redirect(url_for("admin_users", password_changed=1))
        record_audit_event(event_type, "failure", reason_code=reason_code, **audit_target)
    return page(
        "password_change", "회원 비밀번호 변경" if admin_action else "비밀번호 변경",
        member=member, admin_action=admin_action, error=error, status=status,
    )


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    member = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE id = ?", (g.user["id"],)
    ).fetchone()
    if member is None:
        abort(404)
    return password_change_form(member)


@app.route("/admin/users/<int:user_id>/password", methods=["GET", "POST"])
@admin_required
def admin_change_password(user_id):
    if not 1 <= user_id <= 2**63 - 1:
        abort(404)
    member = get_db().execute(
        "SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if member is None:
        abort(404)
    return password_change_form(member, admin_action=True)


@app.get("/notes")
@login_required
def list_notes():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM notes WHERE user_id = ?", (g.user["id"],)).fetchone()[0]
    number, pages = pagination(total)
    notes = db.execute(
        "SELECT id, title, substr(content, 1, 160) AS preview, updated_at FROM notes "
        "WHERE user_id = ? ORDER BY updated_at DESC, id DESC LIMIT ? OFFSET ?",
        (g.user["id"], PAGE_SIZE, (number - 1) * PAGE_SIZE),
    ).fetchall()
    return page(
        "notes", "내 메모", notes=notes, total=total, number=number, pages=pages,
        notice="메모를 삭제했어요." if request.args.get("deleted") == "1" else None,
    )


@app.route("/notes/new", methods=["GET", "POST"])
@login_required
def create_note():
    title, content, error = "", "", None
    if request.method == "POST":
        title, content, error = read_note_form()
        if error is None:
            now = int(time.time())
            db = get_db()
            with db:
                note_id = db.execute(
                    "INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (g.user["id"], title, content, now, now),
                ).lastrowid
                insert_audit_event(db, "note.create", "success", target_type="note", target_id=note_id)
            return redirect(url_for("view_note", note_id=note_id, saved=1))
    return page(
        "note_form", "새 메모", form_title=title, form_content=content,
        cancel_url=url_for("list_notes"), error=error, status=400 if error else 200,
    )


@app.get("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    return page(
        "note_detail", "메모 상세", note=owned_note(note_id),
        notice="메모를 저장했어요." if request.args.get("saved") == "1" else None,
    )


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required
def edit_note(note_id):
    note = owned_note(note_id)
    title, content, error = note["title"], note["content"], None
    if request.method == "POST":
        title, content, error = read_note_form()
        if error is None:
            db = get_db()
            with db:
                result = db.execute(
                    "UPDATE notes SET title = ?, content = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                    (title, content, int(time.time()), note_id, g.user["id"]),
                )
                if result.rowcount != 1:
                    abort(404)
                insert_audit_event(db, "note.update", "success", target_type="note", target_id=note_id)
            return redirect(url_for("view_note", note_id=note_id, saved=1))
    return page(
        "note_form", "메모 수정", form_title=title, form_content=content,
        cancel_url=url_for("view_note", note_id=note_id), error=error, status=400 if error else 200,
    )


@app.route("/notes/<int:note_id>/delete", methods=["GET", "POST"])
@login_required
def delete_note(note_id):
    note = owned_note(note_id)
    if request.method == "POST":
        db = get_db()
        with db:
            result = db.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, g.user["id"]))
            if result.rowcount != 1:
                abort(404)
            insert_audit_event(db, "note.delete", "success", target_type="note", target_id=note_id)
        return redirect(url_for("list_notes", deleted=1))
    return page("note_delete", "메모 삭제", note=note)


@app.get("/admin")
@admin_required
def admin_users():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    number, pages = pagination(total)
    members = db.execute(
        "SELECT id, username, is_admin FROM users ORDER BY id LIMIT ? OFFSET ?",
        (PAGE_SIZE, (number - 1) * PAGE_SIZE),
    ).fetchall()
    return page(
        "admin", "회원 관리", members=members, total=total, number=number, pages=pages,
        notice="회원 비밀번호를 변경하고 해당 회원의 모든 로그인을 종료했습니다." if request.args.get("password_changed") == "1" else None,
    )


AUDIT_SELECT = (
    "SELECT id, created_at, event_type, outcome, actor_username, attempted_username, "
    "target_type, target_id, target_label, source_ip, user_agent, channel, reason_code, request_id "
    "FROM audit_events"
)


@app.get("/admin/audit")
@admin_required
def admin_audit():
    filters, number, _ = read_audit_filters()
    where, values = audit_where(filters)
    db = get_db()
    latest_id = db.execute("SELECT COALESCE(MAX(id), 0) FROM audit_events").fetchone()[0]
    snapshot_where = where + (" AND id <= ?" if where else " WHERE id <= ?")
    snapshot_values = (*values, latest_id)
    total = db.execute("SELECT COUNT(*) FROM audit_events" + snapshot_where, snapshot_values).fetchone()[0]
    pages = max(1, (total + AUDIT_PAGE_SIZE - 1) // AUDIT_PAGE_SIZE)
    if number > pages:
        abort(404)
    rows = db.execute(
        AUDIT_SELECT + snapshot_where + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
        (*snapshot_values, AUDIT_PAGE_SIZE, (number - 1) * AUDIT_PAGE_SIZE),
    ).fetchall()
    events = [audit_event_json(row) for row in rows]
    query = {key: value for key, value in filters.items() if value}
    previous_url = url_for("admin_audit", page=number - 1, **query) if number > 1 else None
    next_url = url_for("admin_audit", page=number + 1, **query) if number < pages else None
    poll_url = url_for("api_admin_audit_events", **query) if number == 1 else None
    return page(
        "audit", "활동 기록", events=events, total=total, summary=audit_summary(db),
        filters=filters, filter_labels=AUDIT_FILTER_LABELS, number=number, pages=pages,
        previous_url=previous_url, next_url=next_url, poll_url=poll_url, latest_id=latest_id,
        retention_days=app.config["AUDIT_RETENTION_DAYS"],
    )


@app.get("/api/admin/audit/events")
@admin_required
def api_admin_audit_events():
    filters, _, after_id = read_audit_filters(polling=True)
    where, values = audit_where(filters, after_id=after_id)
    db = get_db()
    rows = db.execute(AUDIT_SELECT + where + " ORDER BY id ASC LIMIT 101", values).fetchall()
    has_more = len(rows) > 100
    return jsonify(
        events=[audit_event_json(row) for row in rows[:100]],
        has_more=has_more,
        summary=audit_summary(db),
    )


init_db()

if __name__ == "__main__":
    if production:
        raise RuntimeError("Use a production WSGI server with HTTPS instead of app.run().")
    port = os.environ.get("PORT", "8000")
    if re.fullmatch(r"[0-9]{1,5}", port) is None or not 1 <= int(port) <= 65535:
        raise RuntimeError("PORT must be an integer between 1 and 65535.")
    app.run(host="0.0.0.0", port=int(port), debug=False)
