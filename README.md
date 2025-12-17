# FreeCat Sub 🐱

FreeCat Sub 是一个基于 Flask 的轻量级订阅管理系统，专为 FreeCat 用户设计。它允许用户通过邮箱和密码生成专属的安全密钥（Token），并使用该密钥查询流量使用情况、账户信息，以及获取代理订阅链接。

通过使用本系统，您可以避免直接在订阅链接中暴露您的明文账号密码。

## ✨ 主要功能

*   **安全密钥生成**：通过邮箱和密码生成唯一的 32 位 Token，凭据经过 AES 加密存储。
*   **流量仪表盘**：直观展示已用流量（上传/下载）、剩余流量、总流量及使用百分比。
*   **账户信息查看**：查看套餐名称、到期时间、设备限制等信息。
*   **订阅代理**：提供 `/api/sub` 接口，支持在 Clash、V2Ray 等客户端中直接使用生成的 Token 进行订阅，隐藏真实订阅地址。
*   **隐私保护**：所有敏感信息在数据库中均加密存储。

## 🛠️ 部署方式

### 方式一：使用 Docker Compose（推荐）

1.  **克隆或下载本项目**

2.  **配置环境变量（可选）**
    复制 `.env.example` 为 `.env` 并修改配置（如果需要）：
    ```bash
    cp .env.example .env
    ```
    *建议修改 `CIPHER_KEY` 以确保加密安全。*

3.  **启动服务**
    ```bash
    docker-compose up -d --build
    ```

4.  **访问系统**
    浏览器访问：`http://localhost:15000`

### 方式二：手动运行

1.  **安装依赖**
    确保您已安装 Python 3.11+。
    ```bash
    pip install -r requirements.txt
    ```

2.  **设置环境变量（可选）**
    Linux/macOS:
    ```bash
    export CIPHER_KEY="your_secret_key"
    ```
    Windows (PowerShell):
    ```powershell
    $env:CIPHER_KEY="your_secret_key"
    ```

3.  **运行应用**
    ```bash
    python app.py
    ```

4.  **访问系统**
    浏览器访问：`http://localhost:5000`

## ⚙️ 环境变量

| 变量名 | 描述 | 默认值 |
| :--- | :--- | :--- |
| `CIPHER_KEY` | 用于加密数据库中存储的凭据的密钥 | `test1234` |

## 🔌 API 接口说明

*   **生成密钥**: `POST /api/generate-key`
    *   Body: `{ "email": "...", "password": "..." }`
*   **获取订阅信息**: `GET /api/subscribe?key=<token>`
*   **获取订阅内容 (代理)**: `GET /api/sub?key=<token>`
    *   可作为订阅链接直接填入客户端。支持透传查询参数。

## ⚠️ 免责声明

本项目仅供学习和个人使用，请勿用于非法用途。使用本程序产生的任何后果由使用者自行承担。
