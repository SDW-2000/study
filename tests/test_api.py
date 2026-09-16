import importlib.util
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from unittest.mock import patch

from werkzeug.security import generate_password_hash


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"
PASSWORD = "isolated test account passphrase"


class IsolatedApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.database = Path(cls.temporary.name) / "test.db"
        cls.environment = dict(
            os.environ, DATABASE_PATH=str(cls.database), SECRET_KEY=secrets.token_hex(32),
            APP_ENV="development", TRUST_PROXY="0", TRUSTED_HOSTS="localhost,127.0.0.1",
            ADMIN_PASSWORD=PASSWORD, ADMIN_NOTE="SBOB{isolated_api_fixture}",
        )
        spec = importlib.util.spec_from_file_location("isolated_memo_app", APP_PATH)
        cls.module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, cls.environment, clear=True):
            spec.loader.exec_module(cls.module)
        cls.app = cls.module.app
        cls.app.config.update(TESTING=True)
        cls.password_hash = generate_password_hash(PASSWORD)

    def sign_in(self, name="alice"):
        client = self.app.test_client()
        page = client.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = client.post("/login", data={"username": name, "password": PASSWORD, "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        return client, token

    def assert_error(self, response, status):
        self.assertEqual(response.status_code, status)
        self.assertEqual(response.mimetype, "application/json")
        self.assertIsInstance(response.json["error"], str)
        self.assertNotIn("Location", response.headers)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)


class NotesApiTests(IsolatedApp):
    def setUp(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            for table in ("audit_events", "auth_sessions", "auth_limits", "notes", "users"):
                db.execute(f"DELETE FROM {table}")
            db.executemany(
                "INSERT INTO users (id, username, password_hash, is_admin) VALUES (?, ?, ?, ?)",
                [(1, "admin", self.password_hash, 1), (2, "alice", self.password_hash, 0),
                 (3, "bob", self.password_hash, 0)],
            )
        self.client, self.login_token = self.sign_in()
        self.csrf = self.client.get("/api/csrf").json["csrf_token"]

    def create(self, data=None, **kwargs):
        return self.client.post("/api/notes", json=data if data is not None else {"title": "메모"},
                                headers={"X-CSRF-Token": self.csrf}, **kwargs)

    def test_anonymous_api_requests_always_get_json_401(self):
        client = self.app.test_client()
        for method, path in [("GET", "/api/notes"), ("POST", "/api/notes"),
                             ("GET", "/api/notes/1"), ("GET", "/api/csrf"),
                             ("GET", "/api/missing"), ("DELETE", "/api/notes/1"),
                             ("GET", "/api//notes")]:
            with self.subTest(method=method, path=path):
                self.assert_error(client.open(path, method=method), 401)

    def test_login_still_requires_form_csrf_and_rotates_it(self):
        client = self.app.test_client()
        self.assertEqual(client.post("/login", data={"username": "alice", "password": PASSWORD}).status_code, 400)
        self.assertNotEqual(self.csrf, self.login_token)
        self.assert_error(self.client.post("/api/notes", json={"title": "x"},
                                          headers={"X-CSRF-Token": self.login_token}), 400)

    def test_api_csrf_is_session_bound_and_cookie_is_updated(self):
        fresh, _ = self.sign_in("bob")
        response = fresh.get("/api/csrf")
        self.assertRegex(response.json["csrf_token"], r"^[0-9a-f]{64}$")
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])
        self.assertEqual(fresh.get("/api/csrf").json, response.json)
        self.assert_error(fresh.post("/api/notes", json={"title": "x"},
                                    headers={"X-CSRF-Token": self.csrf}), 400)
        self.assert_error(self.client.post("/api/notes", json={"title": "x"}), 400)

    def test_expired_revoked_and_invalid_sessions_are_unauthorized(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE auth_sessions SET expires_at = 1")
        self.assert_error(self.client.get("/api/notes"), 401)
        client, _ = self.sign_in()
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("DELETE FROM auth_sessions")
        self.assert_error(client.get("/api/notes"), 401)
        client.set_cookie("memo_session", "invalid-signature")
        self.assert_error(client.get("/api/csrf"), 401)

    def test_logout_invalidates_a_copied_session(self):
        old_cookie = self.client.get_cookie("memo_session").value
        self.assertEqual(self.client.post("/logout", data={"csrf_token": self.csrf}).status_code, 302)
        other = self.app.test_client()
        other.set_cookie("memo_session", old_cookie)
        self.assert_error(other.get("/api/notes"), 401)

    def test_password_change_invalidates_api_sessions(self):
        other, _ = self.sign_in()
        response = self.client.post("/account/password", data={
            "csrf_token": self.csrf, "current_password": PASSWORD,
            "new_password": "a different long test password", "confirm_password": "a different long test password",
        })
        self.assertEqual(response.status_code, 302)
        self.assert_error(other.get("/api/notes"), 401)

    def test_create_detail_and_list_match_contract(self):
        before = int(time.time())
        response = self.create({"title": "  회의 기록  ", "body": "첫째 줄\n둘째 줄"})
        self.assertEqual(response.status_code, 201)
        note = response.json
        self.assertEqual(set(note), {"id", "title", "body", "created_at", "updated_at"})
        self.assertIsInstance(note["id"], int)
        self.assertEqual(note["title"], "회의 기록")
        self.assertEqual(note["body"], "첫째 줄\n둘째 줄")
        self.assertEqual(note["created_at"], note["updated_at"])
        self.assertRegex(note["created_at"], r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        with closing(sqlite3.connect(self.database)) as db:
            owner, created = db.execute("SELECT user_id, created_at FROM notes WHERE id = ?", (note["id"],)).fetchone()
        self.assertEqual(owner, 2)
        self.assertGreaterEqual(created, before)
        self.assertEqual(self.client.get(response.headers["Location"]).json, note)
        self.assertEqual(self.client.get("/api/notes").json, {"notes": [note]})

    def test_timestamps_are_kst_independent_of_server_timezone(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("INSERT INTO notes VALUES (10, 2, 'time', '', 0, 60)")
        note = self.client.get("/api/notes/10").json
        self.assertEqual(note["created_at"], "1970-01-01 09:00:00")
        self.assertEqual(note["updated_at"], "1970-01-01 09:01:00")

    def test_optional_and_empty_body_are_supported_by_api_and_html(self):
        for data in ({"title": "제목만"}, {"title": "빈 내용", "body": ""}, {"title": "공백", "body": "  \n"}):
            with self.subTest(data=data):
                response = self.create(data)
                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.json["body"], data.get("body", ""))
                path = f'/notes/{response.json["id"]}'
                self.assertIn("아직 내용이 없어요", self.client.get(path).text)
                self.assertNotRegex(self.client.get(path + "/edit").text, r"<textarea[^>]*\brequired\b")
                edit = self.client.post(path + "/edit", data={"csrf_token": self.csrf, "title": "제목 수정", "content": ""})
                self.assertEqual(edit.status_code, 302)
                self.assertEqual(self.client.get(response.headers["Location"]).json["body"], "")

    def test_list_is_not_truncated_or_paginated_and_is_owner_only(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.executemany("INSERT INTO notes VALUES (?, ?, ?, ?, ?, ?)",
                           [(i, 2, f"메모 {i}", "본문" * 300, i, i) for i in range(1, 26)] +
                           [(26, 1, "admin note", "private admin", 26, 26),
                            (27, 3, "bob note", "private bob", 27, 27)])
        notes = self.client.get("/api/notes").json["notes"]
        self.assertEqual([note["id"] for note in notes], list(range(25, 0, -1)))
        self.assertTrue(all(note["body"] == "본문" * 300 for note in notes))

    def test_empty_list(self):
        self.assertEqual(self.client.get("/api/notes").json, {"notes": []})

    def test_foreign_notes_return_same_404_even_for_admin(self):
        note = self.create().json
        for name in ("bob", "admin"):
            other, _ = self.sign_in(name)
            missing = other.get("/api/notes/999999")
            foreign = other.get(f'/api/notes/{note["id"]}')
            self.assert_error(foreign, 404)
            self.assertEqual(missing.json, foreign.json)
            self.assertEqual(other.get("/api/notes").json, {"notes": []})

    def test_note_id_bounds_and_unknown_api_routes(self):
        for path in ("/api/notes/0", "/api/notes/-1", f"/api/notes/{2**100}", "/api/notes/abc", "/api/missing", "/api//notes"):
            self.assert_error(self.client.get(path), 404)
        response = self.client.delete("/api/notes/1")
        self.assert_error(response, 405)
        self.assertIn("GET", response.headers["Allow"])

    def test_invalid_json_types_unknown_fields_and_lengths(self):
        invalid = [[], "text", 42, {}, {"title": None}, {"title": True}, {"title": 1},
                   {"title": ""}, {"title": "   "}, {"title": "a" * 121}, {"title": "a\nb"},
                   {"title": "ok", "body": None}, {"title": "ok", "body": []},
                   {"title": "ok", "body": "x" * 10001}, {"title": "ok", "body": "\x00"},
                   {"title": "ok", "body": "\ud800"}, {"title": "\udfff"},
                   {"title": "ok", "user_id": 1}, {"title": "ok", "is_admin": True},
                   {"title": "ok", "csrf_token": self.csrf}]
        for data in invalid:
            with self.subTest(data=data):
                self.assert_error(self.create(data), 400)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM notes").fetchone()[0], 0)

    def test_json_parsing_media_type_and_request_size(self):
        for raw in ("{", "null", "[" * 2000 + "0" + "]" * 2000):
            self.assert_error(self.client.post("/api/notes", data=raw, content_type="application/json",
                                              headers={"X-CSRF-Token": self.csrf}), 400)
        self.assert_error(self.client.post("/api/notes", data={"title": "x"}), 415)
        self.assert_error(self.client.post("/api/notes", data="x" * (129 * 1024), content_type="application/json",
                                          headers={"X-CSRF-Token": self.csrf}), 413)

    def test_valid_multibyte_boundaries_and_literal_text_rendering(self):
        response = self.create({"title": "가" * 120, "body": "📝" * 10000})
        self.assertEqual(response.status_code, 201)
        self.assertEqual(len(response.json["body"]), 10000)
        response = self.create({"title": "A & B's note", "body": "<em>plain text</em> {{ 2 + 2 }}"})
        self.assertEqual(response.status_code, 201)
        html = self.client.get(f'/notes/{response.json["id"]}').text
        self.assertIn("&lt;em&gt;plain text&lt;/em&gt; {{ 2 + 2 }}", html)
        self.assertNotIn("<em>plain text</em>", html)

    def test_create_rate_limit_is_per_account_and_preserves_retry_after(self):
        for _ in range(30):
            self.assertEqual(self.create().status_code, 201)
        other, _ = self.sign_in()
        token = other.get("/api/csrf").json["csrf_token"]
        response = other.post("/api/notes", json={"title": "limited"}, headers={"X-CSRF-Token": token},
                              environ_overrides={"REMOTE_ADDR": "192.0.2.1"})
        self.assert_error(response, 429)
        self.assertTrue(1 <= int(response.headers["Retry-After"]) <= 60)
        self.assertEqual(self.client.get("/api/notes").status_code, 200)
        # Creating notes must not consume the separate password-change allowance.
        response = self.client.post("/account/password", data={"csrf_token": self.csrf,
            "current_password": PASSWORD, "new_password": "another password for tests",
            "confirm_password": "another password for tests"})
        self.assertEqual(response.status_code, 302)

    def test_api_errors_do_not_expose_internal_exceptions(self):
        with patch.dict(self.app.config, TESTING=False), patch.object(self.app.logger, "error"):
            with patch.object(self.module, "note_json", side_effect=RuntimeError("private-database-detail")):
                response = self.create()
        self.assert_error(response, 500)
        self.assertNotIn("private-database-detail", response.text)

    def test_https_host_cookie_and_security_headers(self):
        with patch.dict(self.app.config, PRODUCTION=True, SESSION_COOKIE_SECURE=True):
            self.assert_error(self.client.get("/api/notes"), 400)
            response = self.client.get("/api/notes", base_url="https://localhost")
            self.assertEqual(response.status_code, 200)
            self.assertIn("max-age=", response.headers["Strict-Transport-Security"])
        self.assert_error(self.client.get("/api/notes", base_url="http://untrusted.example"), 400)

    def test_html_host_error_still_renders_with_favicon(self):
        response = self.client.get("/login", base_url="http://untrusted.example")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.mimetype, "text/html")
        self.assertNotIn("untrusted.example", response.text)
        self.assertIn('href="/static/favicon.ico"', response.text)


class AuditLogTests(IsolatedApp):
    def setUp(self):
        self.module.audit_cleanup_deadline = 0.0
        with closing(sqlite3.connect(self.database)) as db, db:
            for table in ("audit_events", "auth_sessions", "auth_limits", "notes", "users"):
                db.execute(f"DELETE FROM {table}")
            db.executemany(
                "INSERT INTO users (id, username, password_hash, is_admin) VALUES (?, ?, ?, ?)",
                [(1, "admin", self.password_hash, 1), (2, "alice", self.password_hash, 0),
                 (3, "bob", self.password_hash, 0)],
            )

    def clear_audit(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("DELETE FROM audit_events")
            db.execute("DELETE FROM auth_limits")

    def audit_rows(self, where="1=1", params=()):
        with closing(sqlite3.connect(self.database)) as db:
            db.row_factory = sqlite3.Row
            return db.execute(f"SELECT * FROM audit_events WHERE {where} ORDER BY id", params).fetchall()

    def test_login_events_are_structured_and_do_not_store_secrets(self):
        client = self.app.test_client()
        token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").text).group(1)
        failed = client.post("/login", data={"username": "nobody", "password": "unique-secret-canary", "csrf_token": token},
                             environ_overrides={"REMOTE_ADDR": "203.0.113.9"}, headers={"User-Agent": "Audit <script>"})
        self.assertEqual(failed.status_code, 401)
        success = client.post("/login", data={"username": "alice", "password": PASSWORD, "csrf_token": token},
                              environ_overrides={"REMOTE_ADDR": "203.0.113.10"})
        self.assertEqual(success.status_code, 302)
        rows = self.audit_rows("event_type = 'auth.login'")
        self.assertEqual([row["outcome"] for row in rows], ["failure", "success"])
        self.assertIsNone(rows[0]["actor_user_id"])
        self.assertEqual(rows[0]["attempted_username"], "nobody")
        self.assertEqual(rows[0]["reason_code"], "invalid_credentials")
        self.assertEqual(rows[0]["source_ip"], "203.0.113.9")
        self.assertEqual(rows[1]["actor_user_id"], 2)
        self.assertEqual(rows[1]["request_id"], success.headers["X-Request-ID"])
        stored = " ".join(str(value) for row in rows for value in row if value is not None)
        self.assertNotIn("unique-secret-canary", stored)
        self.assertNotIn(token, stored)

    def test_note_changes_and_logout_are_recorded_without_note_content(self):
        client, _ = self.sign_in("alice")
        self.clear_audit()
        csrf = client.get("/api/csrf").json["csrf_token"]
        created = client.post("/api/notes", json={"title": "private title", "body": "private body"},
                              headers={"X-CSRF-Token": csrf})
        note_id = created.json["id"]
        edited = client.post(f"/notes/{note_id}/edit", data={
            "csrf_token": csrf, "title": "changed title", "content": "changed body",
        })
        self.assertEqual(edited.status_code, 302)
        deleted = client.post(f"/notes/{note_id}/delete", data={"csrf_token": csrf})
        self.assertEqual(deleted.status_code, 302)
        self.assertEqual(client.post("/logout", data={"csrf_token": csrf}).status_code, 302)
        rows = self.audit_rows()
        self.assertEqual([row["event_type"] for row in rows],
                         ["note.create", "note.update", "note.delete", "auth.logout"])
        self.assertEqual(rows[0]["channel"], "api")
        self.assertTrue(all(row["actor_username"] == "alice" for row in rows))
        stored = " ".join(str(value) for row in rows for value in row if value is not None)
        for secret in ("private title", "private body", "changed title", "changed body"):
            self.assertNotIn(secret, stored)

    def test_admin_page_and_polling_are_admin_only(self):
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get("/admin/audit").status_code, 302)
        self.assert_error(anonymous.get("/api/admin/audit/events"), 401)

        member, _ = self.sign_in("alice")
        self.clear_audit()
        self.assertEqual(member.get("/admin/audit").status_code, 403)
        denied = member.get("/api/admin/audit/events")
        self.assert_error(denied, 403)
        self.assertEqual(len(self.audit_rows("event_type = 'authorization.admin_denied'")), 2)

        admin, _ = self.sign_in("admin")
        page = admin.get("/admin/audit")
        self.assertEqual(page.status_code, 200)
        self.assertIn("활동 기록", page.text)
        self.assertIn("/static/admin_audit.js", page.text)
        self.assertIn('class="audit-detail-row"', page.text)
        self.assertIn('colspan="6"', page.text)
        self.assertIn("script-src 'self'", page.headers["Content-Security-Policy"])
        polling = admin.get("/api/admin/audit/events?after_id=0")
        self.assertEqual(polling.status_code, 200)
        self.assertEqual(polling.mimetype, "application/json")
        self.assertIn("events", polling.json)
        self.assertIn("summary", polling.json)

    def test_polling_filters_and_validation(self):
        admin, _ = self.sign_in("admin")
        self.clear_audit()
        client = self.app.test_client()
        token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").text).group(1)
        client.post("/login", data={"username": "nobody", "password": "wrong", "csrf_token": token},
                    environ_overrides={"REMOTE_ADDR": "192.0.2.10"})
        response = admin.get("/api/admin/audit/events?after_id=0&outcome=failure&category=auth&ip=192.0.2.10")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json["events"]), 1)
        self.assertEqual(response.json["events"][0]["actor"], "nobody")
        for path in (
            "/api/admin/audit/events?after_id=-1",
            "/api/admin/audit/events?after_id=0&after_id=1",
            "/api/admin/audit/events?after_id=0&outcome=unknown",
            "/api/admin/audit/events?after_id=0&ip=not-an-ip",
        ):
            self.assert_error(admin.get(path), 400)

    def test_login_rate_limit_creates_one_bounded_event(self):
        client = self.app.test_client()
        token = re.search(r'name="csrf_token" value="([^"]+)"', client.get("/login").text).group(1)
        for _ in range(12):
            response = client.post("/login", data={"username": "alice", "password": "wrong", "csrf_token": token},
                                   environ_overrides={"REMOTE_ADDR": "198.51.100.7"})
        self.assertEqual(response.status_code, 429)
        rows = self.audit_rows("event_type = 'auth.login'")
        self.assertEqual(sum(row["outcome"] == "failure" for row in rows), 10)
        self.assertEqual(sum(row["outcome"] == "rate_limited" for row in rows), 1)

    def test_audit_insert_failure_rolls_back_note_creation(self):
        client, _ = self.sign_in("alice")
        self.clear_audit()
        csrf = client.get("/api/csrf").json["csrf_token"]
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'blocked'); END")
        try:
            with patch.dict(self.app.config, TESTING=False), patch.object(self.app.logger, "error"):
                response = client.post("/api/notes", json={"title": "must rollback"},
                                       headers={"X-CSRF-Token": csrf})
            self.assertEqual(response.status_code, 500)
            with closing(sqlite3.connect(self.database)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM notes").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 0)
        finally:
            with closing(sqlite3.connect(self.database)) as db, db:
                db.execute("DROP TRIGGER reject_audit")


class NotesMigrationTests(IsolatedApp):
    def setUp(self):
        self.legacy_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.legacy_dir.cleanup)
        self.legacy = Path(self.legacy_dir.name) / "legacy.db"
        with closing(sqlite3.connect(self.legacy)) as db, db:
            db.executescript("""
                CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 120),
                    content TEXT NOT NULL CHECK(length(content) BETWEEN 1 AND 10000),
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                CREATE INDEX notes_owner_updated ON notes(user_id, updated_at DESC, id DESC);
            """)
            db.execute("INSERT INTO users VALUES (7, 'admin', ?, 1)", (self.password_hash,))
            db.execute("INSERT INTO notes VALUES (42, 7, '기존 메모', '기존 내용', 100, 200)")
        self.environment_for_migration = dict(self.environment, DATABASE_PATH=str(self.legacy))

    def run_migration(self):
        result = subprocess.run([sys.executable, "-c", "import app"], cwd=APP_PATH.parent,
                                env=self.environment_for_migration, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_data_is_backed_up_and_preserved_and_migration_runs_once(self):
        self.run_migration()
        backups = list(self.legacy.parent.glob("*.before-api-v1-*.db"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        with closing(sqlite3.connect(backups[0])) as backup, closing(sqlite3.connect(self.legacy)) as db:
            self.assertEqual(db.execute("SELECT * FROM notes").fetchall(), backup.execute("SELECT * FROM notes").fetchall())
            self.assertEqual(db.execute("SELECT * FROM users").fetchall(), backup.execute("SELECT * FROM users").fetchall())
            self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE name = 'audit_events'").fetchone())
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertIn("notes_owner_updated", [row[1] for row in db.execute("PRAGMA index_list(notes)")])
            with db:
                db.execute("INSERT INTO notes VALUES (43, 7, 'empty', '', 300, 300)")
        self.run_migration()
        self.assertEqual(len(list(self.legacy.parent.glob("*.before-api-v1-*.db"))), 1)

    def test_failed_migration_rolls_back_without_losing_old_notes(self):
        with closing(sqlite3.connect(self.legacy)) as db, db:
            db.execute("PRAGMA ignore_check_constraints = ON")
            db.execute("UPDATE notes SET title = '' WHERE id = 42")
        result = subprocess.run([sys.executable, "-c", "import app"], cwd=APP_PATH.parent,
                                env=self.environment_for_migration, capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        with closing(sqlite3.connect(self.legacy)) as db:
            self.assertEqual(db.execute("SELECT id, content FROM notes").fetchall(), [(42, "기존 내용")])
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name = 'notes_api_v1'").fetchone())

    def test_parallel_workers_migrate_once(self):
        workers = [subprocess.Popen([sys.executable, "-c", "import app"], cwd=APP_PATH.parent,
                                    env=self.environment_for_migration, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                   for _ in range(2)]
        try:
            for worker in workers:
                _, stderr = worker.communicate(timeout=20)
                self.assertEqual(worker.returncode, 0, stderr.decode())
        finally:
            for worker in workers:
                if worker.poll() is None:
                    worker.kill()
                    worker.communicate()
        self.assertEqual(len(list(self.legacy.parent.glob("*.before-api-v1-*.db"))), 1)
        with closing(sqlite3.connect(self.legacy)) as db:
            self.assertEqual(db.execute("SELECT id FROM notes").fetchall(), [(42,)])

    def test_future_schema_version_is_not_downgraded(self):
        with closing(sqlite3.connect(self.legacy)) as db, db:
            db.execute("PRAGMA user_version = 3")
        result = subprocess.run([sys.executable, "-c", "import app"], cwd=APP_PATH.parent,
                                env=self.environment_for_migration, capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        with closing(sqlite3.connect(self.legacy)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual(db.execute("SELECT id FROM notes").fetchall(), [(42,)])


if __name__ == "__main__":
    unittest.main()
