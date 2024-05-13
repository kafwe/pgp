import socket
from typing import Dict
from communication.chunk import chunk
from communication.client import USER_LENGTH_BYTES
from confidentiality.asymetric import PrivateKey
import confidentiality.pgp as pgp

# class User:
#     username: str
#     ip: ststr


class Server:
    _instance = None
    private_key: PrivateKey
    online: Dict[str, str]  # Username -> IP

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, private_key: PrivateKey):
        self.private_key = private_key

    def receive(self, c: socket.socket, private_key: PrivateKey):
        while True:
            data = chunk(c)
            print("New message recieved")

            user_length, message = self._split_header_message(data)

            user = pgp.pgp_decrypt(message[:user_length], private_key).decode()
            encrypted = message[user_length:]

            if user in self.online:
                self.send(self.online[user], encrypted)

    def _split_header_message(self, data: bytes) -> tuple[int, bytes]:
        user_length = int.from_bytes(data[:USER_LENGTH_BYTES], "big")
        data = data[user_length:]

        message = data

        return user_length, message


def start_server(port=9999) -> socket.socket:
    # AF_INET specifies IPV4, SOCK_STREAM specifies a TCP connection
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((socket.gethostname(), port))
    server.listen()
    client, _ = server.accept()
    return client
