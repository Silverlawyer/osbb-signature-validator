import os
import uuid
import time
import json
import urllib.parse
import urllib.request

from flask import Flask, request, session, redirect, url_for, render_template, send_from_directory, abort

import logger
import eusign_wrapper as eu

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROTECTED_DIR = os.path.join(BASE_DIR, "protected_files")

app = Flask(__name__)
app.secret_key = os.environ.get("KEP_SECRET_KEY", os.urandom(32))

logger.init_db()

try:
    eu.initialize()
except Exception as e:
    print("EUSignCP init warning: %s" % e)

# Параметри взаємодії із сервером web-автентифікації АТ "ІІТ" (протокол OAuth 2.0).
# Це офіційний сервіс, що дозволяє відвідувачу прикріпити файл особистого ключа
# (.jks/.dat/.pfx/.zs2) та ввести пароль ПРЯМО У БРАУЗЕРІ, на стороні auth-сервера ІІТ,
# без встановлення будь-яких розширень чи локальних програм. Пароль відвідувача НІКОЛИ
# не передається і не зберігається на нашому сервері.
#
# УВАГА: нижче використано ТЕСТОВІ client_id/client_secret з офіційної документації ІІТ
# (EUWebAuthenticationD.pdf). Вони працюють лише з тестовим ЦСК АТ "ІІТ" і НЕ придатні
# для перевірки справжніх (production) ключів відвідувачів. Для роботи з реальними КЕП
# необхідно отримати від АТ "ІІТ" (supp@iit.org.ua, (093) 151-82-11) робочі client_id
# та client_secret для нашого домену, після чого підставити їх у /etc/kep-server.env.
AUTH_SERVER_DNS = os.environ.get("KEP_AUTH_SERVER_DNS", "auth.js.sign.eu.iit.com.ua")
OAUTH_CLIENT_ID = os.environ.get("KEP_OAUTH_CLIENT_ID", "U0001493034")
OAUTH_CLIENT_SECRET = os.environ.get("KEP_OAUTH_CLIENT_SECRET", "8217ceb2181e6e8140d80c95df4d8614c5fde9de2d123")
OAUTH_REDIRECT_URI = os.environ.get("KEP_OAUTH_REDIRECT_URI", "http://136.115.148.18/oauth/callback")


def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


@app.route("/")
def index():
    return render_template("index.html", visitor=session.get("visitor"))


@app.route("/login-start", methods=["POST"])
def login_start():
    """Фіксує згоду з офертою і перенаправляє відвідувача на сторінку автентифікації АТ ІІТ."""
    ip = _client_ip()
    ua = request.headers.get("User-Agent", "")
    agree = request.form.get("agree")
    session_id = str(uuid.uuid4())
    if not agree:
        logger.log_event(session_id, None, None, None, ip, "login", "/login-start", None, ua, "no_consent")
        return "Необхідно погодитись з Угодою (поставте галочку).", 400
    session["oauth_session_id"] = session_id
    session["oauth_agree_ts"] = time.time()
    logger.log_event(session_id, None, None, None, ip, "login", "/login-start", None, ua, "consent_recorded")
    params = {
        "response_type": "code",
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "state": session_id,
    }
    auth_url = "https://%s/?%s" % (AUTH_SERVER_DNS, urllib.parse.urlencode(params))
    return redirect(auth_url)


@app.route("/oauth/callback")
def oauth_callback():
    ip = _client_ip()
    ua = request.headers.get("User-Agent", "")
    session_id = session.get("oauth_session_id") or str(uuid.uuid4())
    error = request.args.get("error")
    if error:
        logger.log_event(session_id, None, None, None, ip, "login", "/oauth/callback", None, ua, "denied:%s" % error)
        return "Автентифікацію скасовано або відхилено: %s" % error, 400
    code = request.args.get("code")
    if not code:
        logger.log_event(session_id, None, None, None, ip, "login", "/oauth/callback", None, ua, "no_code")
        return "Відсутній код підтвердження автентифікації.", 400
    if not session.get("oauth_agree_ts"):
        logger.log_event(session_id, None, None, None, ip, "login", "/oauth/callback", None, ua, "no_consent")
        return "Необхідно спочатку погодитись з Угодою.", 400
    try:
        token_params = {
            "grant_type": "authorization_code",
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "code": code,
            "redirect_uri": OAUTH_REDIRECT_URI,
        }
        token_url = "https://%s/get-access?%s" % (AUTH_SERVER_DNS, urllib.parse.urlencode(token_params))
        with urllib.request.urlopen(token_url, timeout=15) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
        if "error" in token_data:
            raise Exception(token_data.get("error_description", token_data["error"]))
        access_token = token_data["access_token"]
        user_id = token_data["user_id"]

        info_params = {
            "access_token": access_token,
            "user_id": user_id,
            "fields": "issuercn,serial,subjectcn,surname,givenname,middlename,edrpoucode,drfocode",
        }
        info_url = "https://%s/get-user-info?%s" % (AUTH_SERVER_DNS, urllib.parse.urlencode(info_params))
        with urllib.request.urlopen(info_url, timeout=15) as resp:
            info = json.loads(resp.read().decode("utf-8"))
        if "error" in info:
            raise Exception(info.get("error_description", info["error"]))

        full_name = " ".join(filter(None, [info.get("surname"), info.get("givenname"), info.get("middlename")])) or info.get("subjectcn", "")
        drfo_code = info.get("drfocode", "")
        edrpou_code = info.get("edrpoucode", "")

        session["visitor"] = {
            "session_id": session_id,
            "full_name": full_name,
            "drfo_code": drfo_code,
            "edrpou_code": edrpou_code,
            "issuer_cn": info.get("issuercn", ""),
        }
        logger.log_event(session_id, full_name, drfo_code, edrpou_code, ip, "login", "/oauth/callback", None, ua, "ok_consent_given")
        return redirect(url_for("index"))
    except Exception as e:
        logger.log_event(session_id, None, None, None, ip, "login", "/oauth/callback", None, ua, "denied: %s" % e)
        return "Помилка перевірки підпису: %s" % e, 400


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


def _require_visitor():
    visitor = session.get("visitor")
    if not visitor:
        abort(403)
    return visitor


@app.route("/documents/<path:filename>")
def view_document(filename):
    visitor = _require_visitor()
    ip = _client_ip()
    ua = request.headers.get("User-Agent", "")
    full_path = os.path.join(PROTECTED_DIR, filename)
    if not os.path.isfile(full_path):
        abort(404)
    logger.log_event(visitor["session_id"], visitor["full_name"], visitor["drfo_code"],
                      visitor["edrpou_code"], ip, "view", request.path, filename, ua, "ok")
    return send_from_directory(PROTECTED_DIR, filename)


@app.route("/download/<path:filename>")
def download_document(filename):
    visitor = _require_visitor()
    ip = _client_ip()
    ua = request.headers.get("User-Agent", "")
    full_path = os.path.join(PROTECTED_DIR, filename)
    if not os.path.isfile(full_path):
        abort(404)
    logger.log_event(visitor["session_id"], visitor["full_name"], visitor["drfo_code"],
                      visitor["edrpou_code"], ip, "download", request.path, filename, ua, "ok")
    return send_from_directory(PROTECTED_DIR, filename, as_attachment=True)


@app.route("/terms")
def terms():
    return render_template("terms.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
