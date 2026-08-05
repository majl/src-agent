# 脱敏样例：配置模块（含硬编码凭据，供 secret 检测演示）。
DB_PASSWORD = "Sup3rSecretP@ssw0rd!"          # [VULN] 硬编码数据库口令
API_KEY = "sk-live-1234567890abcdef"          # [VULN] 硬编码 API Key
SECRET_SALT = "static-salt-2024"
