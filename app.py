"""BankTrap: local, synthetic demonstration. Python 3.10+, standard library only."""
import argparse
import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
PATTERNS = [r"\bor\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1['\"]?", r"\bunion\s+(?:all\s+)?select\b"]


def normalized(value):
    return re.sub(r"/\*.*?\*/", " ", value, flags=re.S).lower()


def matches(rule, username):
    return any(re.search(p, normalized(username)) for p in rule["patterns"])


class Store:
    def __init__(self, db):
        self.db = sqlite3.connect(db, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, data TEXT NOT NULL)")
        self.db.commit()
        self.lock = threading.RLock()
        self.rule = None
        self.enabled = False
        self.validation = None
        self.attempts = {}
        self.sessions = {}

    def event(self, kind, session, detail, technique=None, source="honeypot"):
        with self.lock:
            obj = {"timestamp": datetime.now(timezone.utc).isoformat(), "kind": kind,
                   "session": session[:64], "detail": detail[:1000], "technique": technique,
                   "source": source, "evidence": "synthetic-demo"}
            cur = self.db.execute("INSERT INTO events(data) VALUES (?)", (json.dumps(obj, ensure_ascii=False),))
            obj["id"] = cur.lastrowid
            self.db.execute("DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM events)")
            self.db.commit()
            return obj

    def events(self):
        with self.lock:
            return [dict(json.loads(s), id=i) for i, s in self.db.execute("SELECT id,data FROM events ORDER BY id DESC LIMIT 100")]

    def login(self, username, password, session):
        # Passwords never enter the event store. No SQL is executed from input.
        with self.lock:
            if matches({"patterns": PATTERNS}, username):
                self.event("SQLi attempt", session, username, "T1190 (candidate)")
                ok = True
            elif username == "demo-admin" and password == "demo-canary":
                self.event("Decoy account used", session, "Уникальная синтетическая учётная запись", "T1078 (demo)")
                ok = True
            elif username == "client-demo" and password == "demo123":
                self.event("Demo login", session, "Обычный синтетический вход")
                ok = True
            else:
                now = time.monotonic()
                history = [t for t in self.attempts.get(session, []) if now - t < 60]
                history.append(now)
                self.attempts[session] = history[-10:]
                if len(self.attempts) > 1000:
                    self.attempts.pop(next(iter(self.attempts)))
                brute = len(history) >= 5
                self.event("Password guessing" if brute else "Failed login", session,
                           f"Неудачных попыток в этой сессии за 60 с: {len(history)}",
                           "T1110.001 (candidate)" if brute else None)
                ok = False
            if ok:
                self.sessions[session] = time.monotonic()
                if len(self.sessions) > 1000:
                    self.sessions.pop(next(iter(self.sessions)))
            return ok

    def authenticated(self, session):
        return time.monotonic() - self.sessions.get(session, -1e9) < 1800

    def generate(self):
        with self.lock:
            event = next((e for e in self.events() if e["kind"] == "SQLi attempt"), None)
            if not event:
                raise ValueError("Сначала отправьте SQLi в приманку")
            # Template-assisted candidate, not ML or a general-purpose WAF rule.
            self.rule = {"id": "BT-SQLI-001", "version": 1, "format": "banktrap-demo/v1",
                         "method": "POST", "path": "/api/auth/login", "field": "username",
                         "patterns": PATTERNS, "normalization": "lowercase + SQL block comments to spaces",
                         "evidence_event_id": event["id"], "action": "block-in-test-gateway",
                         "scope": "local demonstration only", "status": "draft"}
            self.enabled = False
            self.validation = None
            self.event("Rule drafted", "operator", "BT-SQLI-001: кандидат из библиотеки шаблонов", source="control")
            return self.rule

    def validate(self):
        with self.lock:
            if not self.rule:
                raise ValueError("Сначала создайте правило")
            corpus = json.loads((ROOT / "corpus.json").read_text())
            result = {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "cases": []}
            for case in corpus["acceptance"]:
                hit = matches(self.rule, case["username"])
                category = ("TP" if hit else "FN") if case["attack"] else ("FP" if hit else "TN")
                result[category] += 1
                result["cases"].append({"name": case["name"], "category": category})
            result["known_limitations"] = [{"name": c["name"], "blocked": matches(self.rule, c["username"])}
                                           for c in corpus["limitations"]]
            result["passed"] = result["FN"] == 0 and result["FP"] == 0
            result["corpus_sha256"] = hashlib.sha256((ROOT / "corpus.json").read_bytes()).hexdigest()
            result["scope"] = "Small public synthetic regression set; NOT bank effectiveness evidence"
            self.validation = result
            self.rule["status"] = "validated-demo" if result["passed"] else "rejected"
            self.event("Replay completed", "operator", json.dumps({k: result[k] for k in ("TP", "FN", "FP", "TN")}), source="control")
            return result

    def activate(self):
        with self.lock:
            if not self.validation or not self.validation["passed"]:
                raise ValueError("Нужна успешная проверка кандидата")
            self.enabled = True
            self.event("Test rule enabled", "operator", "Только локальный шлюз", source="control")

    def gateway(self, username):
        with self.lock:
            blocked = bool(self.enabled and self.rule and matches(self.rule, username))
            self.event("Gateway blocked" if blocked else "Gateway passed", "test-gateway",
                       "Бизнес-операция не выполняется", source="gateway")
            return blocked

    def reset(self):
        with self.lock:
            self.db.execute("DELETE FROM events")
            self.db.commit()
            self.rule = self.validation = None
            self.enabled = False
            self.attempts.clear()
            self.sessions.clear()


class Handler(BaseHTTPRequestHandler):
    server_version = "BankTrapDemo/0.1"

    def log_message(self, *_):
        pass

    def reply(self, status, value, content_type="application/json; charset=utf-8"):
        payload = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def allowed(self):
        expected = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        if self.headers.get("Host") not in expected:
            self.reply(403, {"error": "Local host only"})
            return False
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + h for h in expected}:
            self.reply(403, {"error": "Cross-origin requests denied"})
            return False
        if self.path.startswith("/control/") and not secrets.compare_digest(self.headers.get("X-Operator-Token", ""), self.server.token):
            self.reply(401, {"error": "Введите токен оператора из терминала"})
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        path = urlsplit(self.path).path
        files = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "application/javascript"), "/style.css": ("style.css", "text/css")}
        if path in files:
            name, mime = files[path]
            self.reply(200, (ROOT / "static" / name).read_bytes(), mime + "; charset=utf-8")
        elif path == "/health":
            self.reply(200, {"ok": True, "mode": "synthetic-local-demo"})
        elif path == "/control/state":
            with self.server.store.lock:
                s = self.server.store
                self.reply(200, {"events": s.events(), "rule": s.rule, "validation": s.validation, "enabled": s.enabled})
        elif path == "/api/admin/users":
            self.server.store.event("Decoy admin accessed", self.headers.get("X-Demo-Session", "anonymous"),
                                    "Открытый endpoint-приманка; ATT&CK не назначается автоматически")
            self.reply(200, {"synthetic": True, "users": [{"id": "DEMO-001", "name": "Тестовый клиент"}]})
        else:
            self.reply(404, {"error": "Not found"})

    def do_POST(self):
        if not self.allowed():
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0 or length > 8192:
                self.reply(413, {"error": "Maximum body 8192 bytes"})
                return
            if self.headers.get_content_type() != "application/json":
                self.reply(415, {"error": "JSON required"})
                return
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("JSON object required")
            username, password = body.get("username", ""), body.get("password", "")
            if not isinstance(username, str) or not isinstance(password, str) or len(username) > 512 or len(password) > 512:
                raise ValueError("Invalid credentials format")
            s = self.server.store
            session = self.headers.get("X-Demo-Session", "anonymous")[:64]
            if self.path == "/api/auth/login":
                ok = s.login(username, password, session)
                self.reply(200 if ok else 401, {"ok": ok, "synthetic": True, "balance": 125000 if ok else None})
            elif self.path == "/api/transfer":
                if not s.authenticated(session):
                    self.reply(401, {"error": "Войдите в демобанк"})
                    return
                amount = body.get("amount")
                if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not 0 < amount <= 1000000:
                    raise ValueError("Сумма должна быть от 0 до 1 000 000")
                s.event("Synthetic transfer", session, f"Запрос перевода {amount} DEMO; реальные деньги не используются")
                self.reply(200, {"ok": True, "synthetic": True, "message": "Перевод имитирован"})
            elif self.path == "/gateway/login":
                blocked = s.gateway(username)
                self.reply(403 if blocked else 200, {"blocked": blocked, "mode": "test-gateway", "authentication_performed": False})
            elif self.path == "/control/generate":
                self.reply(200, s.generate())
            elif self.path == "/control/validate":
                self.reply(200, s.validate())
            elif self.path == "/control/activate":
                s.activate()
                self.reply(200, {"enabled": True})
            elif self.path == "/control/disable":
                s.enabled = False
                s.event("Test rule disabled", "operator", "Откат в тестовом шлюзе", source="control")
                self.reply(200, {"enabled": False})
            elif self.path == "/control/reset":
                s.reset()
                self.reply(200, {"reset": True})
            else:
                self.reply(404, {"error": "Not found"})
        except (ValueError, TypeError) as exc:
            self.reply(400, {"error": str(exc)})


def create_server(port, db):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.store = Store(db)
    server.token = secrets.token_urlsafe(24)
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default=str(ROOT / "events.sqlite"))
    args = parser.parse_args()
    server = create_server(args.port, args.db)
    print(f"BankTrap: http://127.0.0.1:{server.server_port}\nТокен оператора: {server.token}\nТолько локальное синтетическое демо. Ctrl+C — завершить.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.store.db.close()
