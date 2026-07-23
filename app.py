import os
import json
import uuid
import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = os.environ.get("KEP_SECRET_KEY", os.urandom(32))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
DOCS_FILE = os.path.join(DATA_DIR, "documents.json")
AUDIT_FILE = os.path.join(DATA_DIR, "audit_log.json")
TERMS_FILE = os.path.join(BASE_DIR, "terms.txt")

# ВАЖЛИВО (архітектурне рішення після перевірки документації АТ "ІІТ"):
# Авторизація за КЕП виконується БЕЗ ОПЛАТИ будь-якого договору з АТ "ІІТ".
# Файл ключа та пароль до нього читаються і обробляються ВИКЛЮЧНО в браузері
# відвідувача (клієнтська JS-бібліотека підпису). Пароль НІКОЛИ не передається
# і не зберігається на цьому сервері. Наступний крок - підключення реальної
# клієнтської бібліотеки (безкоштовна "Java-скрипт-бібліотека підпису" АТ "ІІТ").
# Поточна версія реалізує структуру сторінок та потік переходів.

# ТЕСТОВИЙ пароль адмінпанелі (для перевірки на етапі розробки).
# ВАЖЛИВО: перед реальним використанням ОБОВ'ЯЗКОВО змінити цей пароль,
# наприклад задавши змінну середовища ADMIN_PASSWORD на сервері.
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "777")


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def log_audit(event: dict):
    entries = load_json(AUDIT_FILE, [])
    entries.append(event)
    save_json(AUDIT_FILE, entries)


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_auth"):
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    agree = request.form.get("agree")
    if not agree:
        flash("Потрібно погодитися з умовами оферти.")
        return redirect(url_for("index"))

    # ТИМЧАСОВО: реальна клієнтська перевірка підпису (euscp.js) ще підключається.
    # Пароль ключа у цей запит НІКОЛИ не входить (перевірено на стороні шаблону).
    now = datetime.datetime.utcnow().isoformat()
    session["visitor"] = {
        "full_name": "Тестовий відвідувач",
        "logged_in_at": now,
    }
    log_audit({
        "event": "login_placeholder",
        "time": now,
        "path": "/dashboard",
        "agree": True,
        "note": "реальна перевірка КЕП ще не підключена",
    })
    return redirect(url_for("dashboard"))


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
    return render_template("admin.html", docs=docs)


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
    entries = load_json(AUDIT_FILE, [])
    entries = list(reversed(entries))
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
