# 脱敏样例靶机（合成代码，仅用于 BSRC「Agent+」挑战赛 Demo，不含任何真实目标）。
# 内置若干典型 Web 漏洞，供 SAST + LLM 审计流水线演示。
from flask import Flask, request, render_template_string
import sqlite3
import requests
import subprocess
import os

app = Flask(__name__)


@app.route("/login")
def login():
    user = request.args.get("user")
    pwd = request.args.get("pwd")
    # [VULN] SQL 注入：用户输入直接拼接进 SQL
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name='" + user + "' AND pwd='" + pwd + "'")
    return str(cur.fetchall())


@app.route("/search")
def search():
    q = request.args.get("q")
    # [VULN] XSS：用户输入直接渲染进模板
    return render_template_string("<h1>结果:</h1>" + q)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # [VULN] SSRF：用户可控 URL 直接发起服务端请求
    resp = requests.get(url, timeout=5)
    return resp.text


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # [VULN] 命令注入：用户输入拼接到系统命令
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/user")
def user():
    uid = request.args.get("uid")
    # [VULN] IDOR：按 uid 直查，无归属/权限校验
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=" + uid)
    return str(cur.fetchall())


if __name__ == "__main__":
    app.run(port=5000)
