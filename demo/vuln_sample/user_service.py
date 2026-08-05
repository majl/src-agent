# 脱敏样例：用户服务模块（含一处 SQL 注入，供跨文件上下文审计演示）。
import sqlite3


def get_user_by_email(email: str):
    # [VULN] SQL 注入：f-string 拼接
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT id, name, email FROM users WHERE email = '{email}'")
    return cur.fetchone()


def sanitize(name: str) -> str:
    return name.strip()
