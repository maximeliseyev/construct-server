import socket
import json
import sys
import os


import socket
import json
import sys
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import base64


def generate_keypair():
    """Генерируем настоящую X25519 ключевую пару"""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    return private_bytes.hex(), public_bytes.hex()


def send_and_receive(sock, msg):
    sock.send(json.dumps(msg).encode())
    response = sock.recv(4096)
    return json.loads(response.decode())


def register(username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8080))

    private_key, public_key = generate_keypair()
    print(f"Generated keypair")
    print(f"Private: {private_key}")
    print(f"Public: {public_key}")

    msg = {
        "Register": {
            "username": username,
            "password": password,
            "public_key": public_key,
        }
    }
    response = send_and_receive(s, msg)
    print(f"Register response: {response}")

    s.close()
    return response, private_key


def login(username, password):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8080))

    msg = {"Login": {"username": username, "password": password}}
    response = send_and_receive(s, msg)
    print(f"Login response: {response}")

    if "LoginSuccess" in response:
        return s, response["LoginSuccess"]["user_id"]
    return None, None


def get_public_key(sock, username):
    msg = {"GetPublicKey": {"username": username}}
    response = send_and_receive(sock, msg)

    if "PublicKey" in response:
        return response["PublicKey"]["user_id"], response["PublicKey"]["public_key"]
    return None, None


def send_message(sock, from_user, to_user, content):
    msg = {
        "SendMessage": {
            "from": from_user,
            "to": to_user,
            "content": content,
            "timestamp": 1234567890,
            "encrypted": True,
        }
    }
    response = send_and_receive(sock, msg)
    print(f"Send response: {response}")


def encrypt_for_recipient(message, recipient_public_key_hex):
    """Шифруем сообщение для получателя (упрощённая версия для теста)"""
    # Для полноценной реализации нужен ephemeral key + DH
    # Пока просто base64 для теста (TODO: реальное шифрование)
    return base64.b64encode(message.encode()).decode()


def send_encrypted_message(sock, from_user, to_user, message, recipient_public_key):
    encrypted_content = encrypt_for_recipient(message, recipient_public_key)

    msg = {
        "SendMessage": {
            "from": from_user,
            "to": to_user,
            "content": encrypted_content,
            "timestamp": 1234567890,
            "encrypted": True,
        }
    }
    sock.send(json.dumps(msg).encode())
    response = sock.recv(4096)
    print(f"Send response: {response.decode()}")


def listen_for_messages(sock, username):
    print(f"👂 {username} listening for messages... (Ctrl+C to exit)")
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            msg = json.loads(data.decode())
            print(f"\n📨 Received: {msg}")

            if "Message" in msg:
                content = msg["Message"]["content"]
                # Декодируем base64 (пока без расшифровки)
                try:
                    decrypted = base64.b64decode(content).decode()
                    print(f"💬 Content: {decrypted}")
                except:
                    print(f"💬 Encrypted content: {content}")
    except KeyboardInterrupt:
        print(f"\n👋 {username} disconnecting")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "register"
    username = sys.argv[2] if len(sys.argv) > 2 else "alice"
    password = sys.argv[3] if len(sys.argv) > 3 else "password123"

    if action == "register":
        response, private_key = register(username, password)
        print(f"\n✅ User registered! Save your private key:")
        print(f"Private key: {private_key}")

    elif action == "login":
        sock, user_id = login(username, password)
        if sock:
            print(f"✅ Logged in as {user_id}")
            sock.close()

    elif action == "getkey":
        target = sys.argv[4] if len(sys.argv) > 4 else "bob"
        sock, user_id = login(username, password)
        if sock:
            recipient_id, public_key = get_public_key(sock, target)
            if public_key:
                print(f"✅ User {target}:")
                print(f"   User ID: {recipient_id}")
                print(f"   Public key: {public_key}")
            sock.close()

    elif action == "send":
        target = sys.argv[4] if len(sys.argv) > 4 else "bob"
        message = sys.argv[5] if len(sys.argv) > 5 else "Hello encrypted!"

        sock, my_user_id = login(username, password)
        if sock:
            # Получаем user_id и публичный ключ получателя
            recipient_id, public_key = get_public_key(sock, target)
            if public_key:
                print(f"✅ Sending to {target} (ID: {recipient_id})")

                # Шифруем (пока просто base64 для теста)
                encrypted = base64.b64encode(message.encode()).decode()

                msg = {
                    "SendMessage": {
                        "from": my_user_id,  # user_id, не username!
                        "to": recipient_id,  # user_id, не username!
                        "content": encrypted,
                        "timestamp": 1234567890,
                        "encrypted": True,
                    }
                }
                response = send_and_receive(sock, msg)
                print(f"Send response: {response}")
            sock.close()
    elif action == "listen":
        sock, user_id = login(username, password)
        if sock:
            listen_for_messages(sock, username)
            sock.close()
