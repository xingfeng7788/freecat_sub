# -*- coding: UTF-8 -*-
# @Project ：freecat_sub 
# @FileName ：token_utils.py
# @Author ：dingtianlu
# @Date ：2025/11/13 17:28
# @Function  :
import hashlib
import base64
import os
import sqlite3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from contextlib import contextmanager

# 固定的32字节加密密钥
SECRET_KEY = os.getenv('CIPHER_KEY', "test1234")
ENCRYPTION_KEY = hashlib.sha256(str.encode(SECRET_KEY)).digest()  # 32字节
FIXED_IV = b'tfteooysoqamaiuv'  # 16字节固定IV

# 数据库文件路径
DB_PATH = 'tokens.db'


def init_database():
    """初始化数据库表"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # 创建token存储表
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS token_storage
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           token
                           TEXT
                           UNIQUE
                           NOT
                           NULL,
                           encrypted_data
                           TEXT
                           NOT
                           NULL,
                           created_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP
                       )
                       ''')

        # 创建索引提高查询性能
        cursor.execute('''
                       CREATE INDEX IF NOT EXISTS idx_token ON token_storage(token)
                       ''')

        conn.commit()
        conn.close()
        print("数据库初始化成功")

    except Exception as e:
        print(f"数据库初始化错误: {e}")