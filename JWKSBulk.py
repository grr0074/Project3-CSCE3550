from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2 import PasswordHasher
import uuid
import os

hostName = "localhost"
serverPort = 8080

# SQLite database setup
db_filename = "your_database.db"
conn = sqlite3.connect(db_filename)
cursor = conn.cursor()

# Create the keys table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')

# Create the users table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
''')

# Create the auth_logs table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

conn.commit()

# Function to save a private key to the database
def save_private_key_to_db(key, exp):
    cursor.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key, exp))
    conn.commit()

# Function to retrieve a valid (unexpired) key from the database
def get_valid_private_key():
    now = int(datetime.datetime.utcnow().timestamp())
    cursor.execute('SELECT key FROM keys WHERE exp > ?', (now,))
    key_data = cursor.fetchone()
    return key_data[0] if key_data else None

# Function to retrieve all valid (unexpired) keys from the database
def get_all_valid_private_keys():
    now = int(datetime.datetime.utcnow().timestamp())
    cursor.execute('SELECT key FROM keys WHERE exp > ?', (now,))
    return [row[0] for row in cursor.fetchall()]

# Function to retrieve an expired key from the database (for testing)
def get_expired_private_key():
    cursor.execute('SELECT key FROM keys WHERE exp < ? LIMIT 1', (int(datetime.datetime.utcnow().timestamp()),))
    key_data = cursor.fetchone()
    return key_data[0] if key_data else None

# Function to log authentication request
def log_authentication_request(request_ip, user_id):
    cursor.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request_ip, user_id))
    conn.commit()

# AES Encryption of Private Keys
AES_KEY = os.environ.get('NOT_MY_KEY').encode('utf-8')

def encrypt_private_key(private_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(private_key.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_private_key(encrypted_private_key):
    encrypted_data = base64.b64decode(encrypted_private_key.encode('utf-8'))
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# User Registration
ph = PasswordHasher()

def generate_secure_password():
    return str(uuid.uuid4())

def hash_password(password):
    return ph.hash(password)

def register_user(username, email):
    password = generate_secure_password()
    hashed_password = hash_password(password)

    cursor.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                   (username, hashed_password, email))
    conn.commit()

    return {"password": password}

# HTTP Server Class
class MyServer(BaseHTTPRequestHandler):

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            headers = {"kid": "goodKID"}
            private_key_data = get_valid_private_key()

            if 'expired' in params:
                headers["kid"] = "expiredKID"
                private_key_data = get_expired_private_key()

            if private_key_data:
                encoded_jwt = jwt.encode(token_payload, private_key_data, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))

                # Log authentication request
                request_ip = self.client_address[0]
                log_authentication_request(request_ip, user_id)

            else:
                self.send_response(500)
                self.end_headers()
            return

        elif parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))

            username = data.get('username')
            email = data.get('email')

            result = register_user(username, email)
            self.send_response(201)
            self.end_headers()
            self.wfile.write(bytes(json.dumps(result), "utf-8"))
            return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            # Append keys from the database
            keys_from_db = get_all_valid_private_keys()
            for i, key_data in enumerate(keys_from_db):
                key = serialization.load_pem_private_key(key_data, password=None)
                key_info = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": f"db_key_{i}",
                    "n": int_to_base64(key.public_key().public_numbers.n),
                    "e": int_to_base64(key.public_key().public_numbers.e),
                }
                keys["keys"].append(key_info)
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
