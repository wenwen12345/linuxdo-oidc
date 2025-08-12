#!/usr/bin/env python3

import jwt
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 从环境变量加载私钥
import os
private_key_pem = os.getenv("PRIVATE_KEY")
if not private_key_pem:
    print("错误：未找到PRIVATE_KEY环境变量")
    exit(1)

private_key = serialization.load_pem_private_key(
    private_key_pem.encode('utf-8'), password=None, backend=default_backend()
)

# Test payload
import time
now = int(time.time())
payload = {
    "iss": "https://test.liaowen.eu.org",
    "sub": "123",
    "aud": "test-client",
    "exp": now + 3600,  # 1小时后过期
    "iat": now,
    "name": "test user"
}

# Convert private key to PEM format for PyJWT
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,  
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

headers = {
    "alg": "RS256",
    "typ": "JWT", 
    "kid": "rsa-key-1"
}

try:
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=headers)
    print(f"Token generated successfully: {token[:50]}...")
    
    # 从私钥生成公钥进行测试
    public_key = private_key.public_key()
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    decoded = jwt.decode(token, public_key_pem, algorithms=["RS256"])
    print(f"Token decoded successfully: {decoded}")
    
except Exception as e:
    print(f"JWT Error: {e}")