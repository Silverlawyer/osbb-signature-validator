import os
import json
import uuid
import base64
import secrets
import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

import eusign_wrapper
import logger as audit_db

app = Flask(__name__)
app.secret_key = os.environ.get("KEP_SECRET_KEY", os.urandom(32))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DOCS_FILE = os.path.join(DATA_DIR, "documents.json")
TERMS_FILE = os.path.join(BASE_DIR, "terms.txt")

# ВАЖЛИВО (архітектурне рішення після перевірки документації АТ "ІІТ"):
# Авторизація за КЕП виконується БЕЗ ОПЛАТИ будь-якого договору з АТ "ІІТ".
# Файл ключа та пароль до нього НІКОЛИ не потрапляють і не зберігаються на
# цьому сервері. Відвідувач підписує одноразовий випадковий виклик (challenge)
# безпосередньо у своєму браузері (безкоштовний Web-віджет АТ "ІІТ") або
# локальним агентом "ІІТ Користувач ЦСК" (для апаратних токенів/хмарних
# ключів), а сервер лише перевіряє готовий підпис через офіційну нативну
# бібліотеку EUSignCP, встановлену на цьому сервері, і виймає з нього
# ПІБ та РНОКПП/ЄДРПОУ підписувача.
#
# ТЕСТОВИЙ пароль адмінпанелі (для перевірки на етапі розробки).
# ВАЖЛИВО: перед реальним використанням ОБОВ'ЯЗКОВО змінити цей пароль,
# наприклад задавши змінну середовища ADMIN_PASSWORD на сервері.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "777")

# --- ініціалізація реальної крипто-бібліотеки АТ "ІІТ" на сервері ---
EUSIGN_READY = False
EUSIGN_INIT_ERROR = None
try:
    eusign_wrapper.initialize()
    EUSIGN_READY = True
except Exception as exc:  # noqa: BLE001
    EUSIGN_INIT_ERROR = str(exc)

audit_db.init_db()


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def log_event(session_id, full_name, drfo_code, edrpou_code, action, path, file_name, result):
    audit_db.log_event(
        session_id=session_id,
        full_name=full_name,
        drfo_code=drfo_code,
        edrpou_code=edrpou_code,
        ip_address=request.remote_addr,
        action=action,
        path=path,
        file_name=file_name,
        user_agent=request.headers.get("User-Agent", ""),
        result=result,
    )


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_auth"):
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return render_template("index.html", eusign_ready=EUSIGN_READY, eusign_error=EUSIGN_INIT_ERROR)


@app.route("/auth/challenge")
def auth_challenge():
    challenge = secrets.token_hex(32)
    session["kep_challenge"] = challenge
    return jsonify({"challenge": challenge})


@app.route("/auth/verify", methods=["POST"])
def auth_verify():
    data = request.get_json(silent=True) or {}
    agree = bool(data.get("agree"))
    signed_b64 = (data.get("signed_data") or "").strip()
    challenge = session.get("kep_challenge")
    session_id = str(uuid.uuid4())

    if not agree:
        log_event(session_id, None, None, None, "login", "/", None, "відмова: не погодився з офертою")
        return jsonify({"ok": False, "message": "Потрібно погодитися з умовами оферти."}), 400

    if not challenge:
        return jsonify({"ok": False, "message": "Сесія входу прострочена. Оновіть сторінку і спробуйте ще раз."}), 400

    if not EUSIGN_READY:
        log_event(session_id, None, None, None, "login", "/", None,
                   "відмова: крипто-бібліотеку не ініціалізовано (%s)" % EUSIGN_INIT_ERROR)
        return jsonify({"ok": False, "message": "Крипто-бібліотеку не вдалося ініціалізувати на сервері. Повідомте адміністратора."}), 500

    if not signed_b64:
        return jsonify({"ok": False, "message": "Не отримано підписані дані від засобу підпису."}), 400

    try:
        signed_bytes = base64.b64decode(signed_b64)
    except Exception:
        return jsonify({"ok": False, "message": "Невірний формат підписаних даних."}), 400

    try:
        result = eusign_wrapper.verify_internal(signed_bytes)
    except eusign_wrapper.EuSignError as exc:
        log_event(session_id, None, None, None, "login", "/", None, "відмова: %s" % exc)
        return jsonify({"ok": False, "message": "Підпис не пройшов перевірку: %s" % exc}), 400

    full_name = result.get("full_name")
    drfo_code = result.get("drfo_code")
    edrpou_code = result.get("edrpou_code")
    signed_content = result.get("data") or b""
    try:
        signed_text = signed_content.decode("utf-8")
    except Exception:
        signed_text = ""

    if signed_text != challenge:
        log_event(session_id, full_name, drfo_code, edrpou_code, "login", "/", None,
                   "відмова: підпис не відповідає запиту (можлива повторна атака)")
        return jsonify({"ok": False, "message": "Підпис не відповідає поточному запиту на вхід."}), 400

    session.pop("kep_challenge", None)
    session["visitor"] = {
        "full_name": full_name or "Відвідувач",
        "drfo_code": drfo_code,
        "edrpou_code": edrpou_code,
        "logged_in_at": datetime.datetime.utcnow().isoformat(),
        "session_id": session_id,
    }
    log_event(session_id, full_name, drfo_code, edrpou_code, "login", "/dashboard", None, "успішно")
    return jsonify({"ok": True, "redirect": url_for("dashboard")})


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("visitor", None)
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if "visitor" not in session:
        return redirect(url_for("index"))
    docs = load_json(DOCS_FILE, [])
    categories = {}
    for d in docs:
        categories.setdefault(d.get("category", "Інше"), []).append(d)
    return render_template("dashboard.html", categories=categories, visitor=session["visitor"])


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        next_url = request.form.get("next") or url_for("admin")
        if password == ADMIN_PASSWORD:
            session["admin_auth"] = True
            return redirect(next_url)
        flash("Невірний пароль.")
        return redirect(url_for("admin_login", next=next_url))
    next_url = request.args.get("next") or url_for("admin")
    return render_template("admin_login.html", next=next_url)


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin_auth", None)
    return redirect(url_for("index"))


@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    if request.method == "POST":
        docs = load_json(DOCS_FILE, [])
        docs.append({
            "id": str(uuid.uuid4()),
            "category": request.form.get("category", "").strip() or "Інше",
            "name": request.form.get("name", "").strip(),
            "description": request.form.get("description", "").strip(),
        })
        save_json(DOCS_FILE, docs)
        return redirect(url_for("admin"))
    docs = load_json(DOCS_FILE, [])
    return render_template("admin.html", docs=docs, eusign_ready=EUSIGN_READY, eusign_error=EUSIGN_INIT_ERROR)


@app.route("/admin/delete/<doc_id>", methods=["POST"])
@admin_required
def admin_delete(doc_id):
    docs = load_json(DOCS_FILE, [])
    docs = [d for d in docs if d.get("id") != doc_id]
    save_json(DOCS_FILE, docs)
    return redirect(url_for("admin"))


@app.route("/admin/log")
@admin_required
def admin_log():
    rows = audit_db.fetch_recent(200)
    entries = [
        {
            "ts": r[0], "full_name": r[1], "drfo_code": r[2], "ip_address": r[3],
            "action": r[4], "path": r[5], "file_name": r[6], "result": r[7],
        }
        for r in rows
    ]
    return render_template("admin_log.html", entries=entries)


@app.route("/terms")
def terms():
    text = "Текст оферти буде додано адміністратором пізніше."
    if os.path.exists(TERMS_FILE):
        with open(TERMS_FILE, "r", encoding="utf-8") as f:
            text = f.read()
    return render_template("terms.html", text=text)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
