import socket
import json
import sys


def create_client(user_id):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8080))

    # Login
    login_msg = {"Login": {"user_id": user_id}}
    s.send(json.dumps(login_msg).encode())
    response = s.recv(1024)
    print(f"[{user_id}] Login response:", response.decode())

    return s


def send_message(sock, from_user, to_user, content):
    msg = {
        "SendMessage": {
            "from": from_user,
            "to": to_user,
            "content": content,
            "timestamp": 1234567890,
        }
    }
    sock.send(json.dumps(msg).encode())
    response = sock.recv(1024)
    print(f"Send response:", response.decode())


def listen(sock, user_id):
    while True:
        try:
            data = sock.recv(1024)
            if data:
                print(f"[{user_id}] Received:", data.decode())
        except:
            break


if __name__ == "__main__":
    user_id = sys.argv[1] if len(sys.argv) > 1 else "user1"

    client = create_client(user_id)

    if user_id == "user1":
        # user1 отправляет сообщение user2
        input("Press Enter to send message to user2...")
        send_message(client, "user1", "user2", "Hello user2!")
    else:
        # user2 просто слушает
        print(f"[{user_id}] Listening for messages...")
        listen(client, user_id)

    client.close()
