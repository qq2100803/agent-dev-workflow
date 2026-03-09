"""
用户登录功能实现
"""

from flask import Flask, request, jsonify
import jwt
import datetime
import hashlib

app = Flask(__name__)

# 密钥配置
SECRET_KEY = "your-secret-key-change-in-production"
TOKEN_EXPIRE_HOURS = 24

# 模拟用户数据库
USERS = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password_hash": hashlib.sha256("admin123".encode()).hexdigest(),
        "name": "管理员"
    }
}


def hash_password(password: str) -> str:
    """密码哈希"""
    return hashlib.sha256(password.encode()).hexdigest()


def generate_token(user_id: int, username: str) -> str:
    """生成 JWT Token"""
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRE_HOURS),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


@app.route("/api/auth/login", methods=["POST"])
def login():
    """用户登录接口"""
    data = request.get_json()
    
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({
            "success": False,
            "message": "用户名和密码不能为空"
        }), 400
    
    # 验证用户
    user = USERS.get(username)
    if not user:
        return jsonify({
            "success": False,
            "message": "用户不存在"
        }), 401
    
    # 验证密码
    if user["password_hash"] != hash_password(password):
        return jsonify({
            "success": False,
            "message": "密码错误"
        }), 401
    
    # 生成 Token
    token = generate_token(user["id"], user["username"])
    
    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "name": user["name"]
        }
    })


@app.route("/api/auth/verify", methods=["POST"])
def verify_token():
    """验证 Token"""
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({
            "success": False,
            "message": "无效的 Authorization 头"
        }), 401
    
    token = auth_header[7:]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({
            "success": True,
            "user": {
                "id": payload["user_id"],
                "username": payload["username"]
            }
        })
    except jwt.ExpiredSignatureError:
        return jsonify({
            "success": False,
            "message": "Token 已过期"
        }), 401
    except jwt.InvalidTokenError:
        return jsonify({
            "success": False,
            "message": "无效的 Token"
        }), 401


if __name__ == "__main__":
    app.run(debug=True, port=3000)
