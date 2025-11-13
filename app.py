import os

from flask import Flask, request, jsonify, render_template_string
import requests
from datetime import datetime
from cryptography.fernet import Fernet
import json
import base64
KEY = os.getenv('CIPHER_KEY')
CIPHER_SUITE = Fernet(str.encode(KEY))
app = Flask(__name__)

# API 地址
LOGIN_URL = "https://bobapi.kkhhyytt.cn/api/v1/passport/auth/login"
SUBSCRIBE_URL = "https://bobapi.kkhhyytt.cn/api/v1/user/getSubscribe"


def login(email, password):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Content-Type': 'application/json',
        'Origin': 'https://us.freecat.cc',
        'Referer': 'https://us.freecat.cc/',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    }

    data = {
        "email": email,
        "password": password
    }

    try:
        response = requests.post(LOGIN_URL, headers=headers, json=data, timeout=10)
        response.raise_for_status()
        result = response.json()

        if 'data' in result and 'auth_data' in result['data']:
            return result['data']['auth_data'], result['data']['token']
        else:
            return None, None
    except Exception as e:
        return None, None


def get_subscribe_info(auth_data):
    headers = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Authorization': auth_data,
        'Origin': 'https://us.freecat.cc',
        'Referer': 'https://us.freecat.cc/',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
    }

    try:
        response = requests.get(SUBSCRIBE_URL, headers=headers, timeout=10)
        response.raise_for_status()
        result = response.json()

        if 'data' in result:
            return result['data']
        else:
            return None
    except Exception as e:
        return None


def login_get_subscribe_info(email, password):
    try:
        # 步骤1: 登录
        auth_data, token = login(email, password)
        if not auth_data:
            return {
                'success': False,
                'message': '登录失败，请检查邮箱和密码',
                'code': 401
            }

        # 步骤2: 获取订阅信息
        subscribe_info = get_subscribe_info(auth_data)
        if not subscribe_info:
            return {
                'success': False,
                'message': '获取订阅信息失败',
                'code': 500
            }

        # 步骤3: 格式化订阅信息
        upload = subscribe_info.get('u', 0)
        download = subscribe_info.get('d', 0)
        total = subscribe_info.get('transfer_enable', 0)
        used = upload + download
        remaining = total - used
        usage_percent = (used / total * 100) if total > 0 else 0

        expired_at = subscribe_info.get('expired_at')
        if expired_at:
            expire_date = datetime.fromtimestamp(expired_at).strftime('%Y-%m-%d %H:%M:%S')
        else:
            expire_date = "不限时间"

        # 构建返回数据
        result = {
            'success': True,
            'message': '获取成功',
            'code': 200,
            'data': {
                'user_info': {
                    'email': subscribe_info.get('email', ''),
                    'plan_name': subscribe_info.get('plan', {}).get('name', '未知套餐'),
                    'expire_date': expire_date,
                    'device_limit': subscribe_info.get('device_limit') or "无限制",
                    'alive_ip': subscribe_info.get('alive_ip', 0)
                },
                'traffic_info': {
                    'upload': upload,
                    'download': download,
                    'total': total,
                    'used': used,
                    'remaining': remaining,
                    'usage_percent': round(usage_percent, 2),
                    'upload_formatted': format_bytes(upload),
                    'download_formatted': format_bytes(download),
                    'total_formatted': format_bytes(total),
                    'used_formatted': format_bytes(used),
                    'remaining_formatted': format_bytes(remaining)
                },
                'subscribe_url': subscribe_info.get('subscribe_url', ''),
                'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        }

        return result

    except Exception as e:
        return {
            'success': False,
            'message': f'服务器内部错误: {str(e)}',
            'code': 500
        }


def get_subscription_data(subscribe_url):
    try:
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
            'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
        }

        # 发送GET请求
        response = requests.get(subscribe_url, headers=headers)
        response.raise_for_status()
        # 输出响应内容
        print(f"Status Code: {response.status_code}")
        print("Response Body:")
        return response.text
    except Exception as e:
        raise e


def format_bytes(bytes_num):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.2f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.2f} PB"


def encrypt_credentials(email, password):
    """
    使用 Fernet 对称加密简化加密 email 和 password
    返回加密后的字符串
    """
    # 将 email 和 password 转换为 JSON 格式
    credentials = json.dumps({"email": email, "password": password})

    # 使用 Fernet 加密
    encrypted = CIPHER_SUITE.encrypt(credentials.encode())

    # 将加密结果转换为 URL 安全的 Base64 编码字符串
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_credentials(key):
    """
    使用 Fernet 对称解密简化解密
    返回解密后的 email 和 password
    """
    try:
        # 将 Base64 编码的字符串解码为字节
        encrypted = base64.urlsafe_b64decode(key.encode())

        # 使用 Fernet 解密
        decrypted = CIPHER_SUITE.decrypt(encrypted)

        # 将解密后的 JSON 字符串解析为字典
        credentials = json.loads(decrypted.decode())
        return credentials["email"], credentials["password"]
    except Exception as e:
        # 捕获异常并返回 None
        print(f"解密失败: {e}")
        return None, None


@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            'success': False,
            'message': '邮箱和密码不能为空',
            'code': 400
        }), 400

    key = encrypt_credentials(email, password)
    return jsonify({
        'success': True,
        'message': '秘钥生成成功',
        'code': 200,
        'data': {
            'key': key
        }
    })


@app.route('/api/subscribe', methods=['GET'])
def get_subscribe():
    key = request.args.get('key')

    if not key:
        return jsonify({
            'success': False,
            'message': '秘钥不能为空',
            'code': 400
        }), 400

    email, password = decrypt_credentials(key)
    if not email or not password:
        return jsonify({
            'success': False,
            'message': '无效的秘钥',
            'code': 401
        }), 401

    result = login_get_subscribe_info(email, password)
    return jsonify(result)


@app.route('/api/sub', methods=['GET'])
def subscribe_data():
    key = request.args.get('key')

    if not key:
        return jsonify({
            'success': False,
            'message': '秘钥不能为空',
            'code': 400
        }), 400

    email, password = decrypt_credentials(key)
    if not email or not password:
        return jsonify({
            'success': False,
            'message': '无效的秘钥',
            'code': 401
        }), 401

    try:
        result = login_get_subscribe_info(email, password)
        if not result['success']:
            return jsonify(result), result['code']

        subscribe_url = result['data']['subscribe_url']
        if subscribe_url:
            subscription_data = get_subscription_data(subscribe_url)
            return subscription_data if subscription_data else jsonify({
                'success': False,
                'message': '获取订阅数据失败',
                'code': 500
            }), 500
        else:
            return jsonify({
                'success': False,
                'message': '订阅链接为空',
                'code': 404
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'服务器内部错误: {str(e)}',
            'code': 500
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'success': True,
        'message': 'API服务正常运行',
        'code': 200,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/', methods=['GET'])
def index():
    html = '''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>订阅管理系统</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
            }
            .card {
                background: white;
                border-radius: 12px;
                padding: 30px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 28px;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
                font-size: 14px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 8px;
                color: #555;
                font-weight: 500;
            }
            input {
                width: 100%;
                padding: 12px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 14px;
                transition: border-color 0.3s;
            }
            input:focus {
                outline: none;
                border-color: #667eea;
            }
            .btn-group {
                display: flex;
                gap: 10px;
                margin-top: 25px;
            }
            button {
                flex: 1;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
            }
            .btn-primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
            }
            .btn-secondary {
                background: #f5f5f5;
                color: #666;
            }
            .btn-secondary:hover {
                background: #e0e0e0;
            }
            .result {
                margin-top: 20px;
                display: none;
            }
            .info-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin: 20px 0;
            }
            .info-item {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                border-left: 4px solid #667eea;
            }
            .info-label {
                font-size: 12px;
                color: #888;
                margin-bottom: 5px;
            }
            .info-value {
                font-size: 16px;
                color: #333;
                font-weight: 600;
            }
            .progress-bar {
                width: 100%;
                height: 20px;
                background: #e0e0e0;
                border-radius: 10px;
                overflow: hidden;
                margin: 15px 0;
            }
            .progress-fill {
                height: 100%;
                background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
                transition: width 0.5s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-size: 12px;
                font-weight: 600;
            }
            .key-display {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 8px;
                word-break: break-all;
                font-family: monospace;
                font-size: 12px;
                margin: 15px 0;
                border: 2px dashed #667eea;
            }
            .copy-btn {
                background: #667eea;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
                margin-top: 10px;
            }
            .copy-btn:hover {
                background: #5568d3;
            }
            .alert {
                padding: 12px 16px;
                border-radius: 8px;
                margin-top: 15px;
            }
            .alert-success {
                background: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }
            .alert-error {
                background: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            .loading {
                display: none;
                text-align: center;
                padding: 20px;
            }
            .spinner {
                border: 3px solid #f3f3f3;
                border-top: 3px solid #667eea;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 0 auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            .hidden {
                display: none;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <h1>🚀 订阅管理系统</h1>
                <p class="subtitle">生成密钥并查询订阅信息</p>

                <form id="subscribeForm">
                    <div class="form-group">
                        <label for="email">📧 邮箱地址</label>
                        <input type="email" id="email" name="email" placeholder="请输入您的邮箱" required>
                    </div>
                    <div class="form-group">
                        <label for="password">🔒 密码</label>
                        <input type="password" id="password" name="password" placeholder="请输入您的密码" required>
                    </div>
                    <div class="btn-group">
                        <button type="submit" class="btn-primary">生成密钥并查询</button>
                        <button type="button" class="btn-secondary" onclick="resetForm()">重置</button>
                    </div>
                </form>

                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p style="margin-top: 10px; color: #666;">正在查询中...</p>
                </div>

                <div class="result" id="result"></div>
            </div>
        </div>

        <script>
            document.getElementById('subscribeForm').addEventListener('submit', async function(event) {
                event.preventDefault();

                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                const resultDiv = document.getElementById('result');
                const loadingDiv = document.getElementById('loading');

                // 显示加载动画
                loadingDiv.style.display = 'block';
                resultDiv.style.display = 'none';

                try {
                    // 第一步：生成密钥
                    const keyResponse = await fetch('/api/generate-key', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ email, password })
                    });

                    const keyData = await keyResponse.json();

                    if (!keyData.success) {
                        throw new Error(keyData.message);
                    }

                    const key = keyData.data.key;

                    // 第二步：获取订阅信息
                    const subResponse = await fetch(`/api/subscribe?key=${encodeURIComponent(key)}`);
                    const subData = await subResponse.json();

                    if (!subData.success) {
                        throw new Error(subData.message);
                    }

                    // 隐藏加载动画
                    loadingDiv.style.display = 'none';

                    // 显示结果
                    displayResult(key, subData.data);

                } catch (error) {
                    loadingDiv.style.display = 'none';
                    resultDiv.style.display = 'block';
                    resultDiv.innerHTML = `<div class="alert alert-error">❌ ${error.message}</div>`;
                }
            });

            function displayResult(key, data) {
                const resultDiv = document.getElementById('result');
                const userInfo = data.user_info;
                const trafficInfo = data.traffic_info;

                resultDiv.innerHTML = `
                    <div class="alert alert-success">✅ 查询成功！</div>

                    <h3 style="margin-top: 25px; color: #333;">🔑 您的专属密钥</h3>
                    <div class="key-display">${key}</div>
                    <div style="display: flex; gap: 10px;">
                        <button class="copy-btn" onclick="copyKey('${key}')">📋 复制密钥</button>
                        <button class="copy-btn" onclick="copySubscribeLink('${key}')">🔗 复制订阅接口</button>
                    </div>

                    <h3 style="margin-top: 25px; color: #333;">👤 账户信息</h3>
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">邮箱</div>
                            <div class="info-value">${userInfo.email}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">套餐</div>
                            <div class="info-value">${userInfo.plan_name}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">到期时间</div>
                            <div class="info-value">${userInfo.expire_date}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">设备限制</div>
                            <div class="info-value">${userInfo.device_limit}</div>
                        </div>
                    </div>

                    <h3 style="margin-top: 25px; color: #333;">📊 流量使用情况</h3>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${trafficInfo.usage_percent}%">
                            ${trafficInfo.usage_percent}%
                        </div>
                    </div>
                    <div class="info-grid">
                        <div class="info-item">
                            <div class="info-label">已上传</div>
                            <div class="info-value">${trafficInfo.upload_formatted}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">已下载</div>
                            <div class="info-value">${trafficInfo.download_formatted}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">总流量</div>
                            <div class="info-value">${trafficInfo.total_formatted}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">剩余流量</div>
                            <div class="info-value">${trafficInfo.remaining_formatted}</div>
                        </div>
                    </div>

                    <h3 style="margin-top: 25px; color: #333;">🔗 订阅链接</h3>
                    <div class="key-display">${data.subscribe_url}</div>
                    <button class="copy-btn" onclick="copyKey('${data.subscribe_url}')">📋 复制订阅链接</button>

                    <p style="margin-top: 20px; color: #888; font-size: 12px;">
                        更新时间: ${data.updated_at}
                    </p>
                `;

                resultDiv.style.display = 'block';
            }

            function copyKey(text) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('✅ 已复制到剪贴板！');
                }).catch(err => {
                    alert('❌ 复制失败，请手动复制');
                });
            }

            function copySubscribeLink(key) {
                const host = window.location.origin;
                const subscribeLink = `${host}/api/sub?key=${encodeURIComponent(key)}`;
                navigator.clipboard.writeText(subscribeLink).then(() => {
                    alert('✅ 订阅接口链接已复制到剪贴板！');
                }).catch(err => {
                    alert('❌ 复制失败，请手动复制');
                });
            }

            function resetForm() {
                document.getElementById('subscribeForm').reset();
                document.getElementById('result').style.display = 'none';
            }
        </script>
    </body>
    </html>
    '''
    return render_template_string(html)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)