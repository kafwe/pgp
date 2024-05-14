from collections import defaultdict
from os import urandom
import socket
import threading
from typing import Callable
from communication.chunk import chunk
from communication.client import DEST_LENGTH_BYTES
from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    load_private_key,
    public_key_from_bytes,
)
import confidentiality.pgp as pgp
import socket

# class User:
#     username: str
#     ip: ststr

CERTIFICATE_LENGTH_BYTES = 8


class _Server:
    private_key: PrivateKey
    online: dict[str, socket.socket]  # Username -> socket
    # Username -> list of messages to receive
    send_queue: dict[str, list[bytes]]
    sock: socket.socket
    shutdown = False

    def __init__(self, sock: socket.socket, private_key: PrivateKey):
        self.private_key = private_key
        self.sock = sock
        self.online = {}
        self.send_queue = defaultdict(list)

    def receive(self, c: socket.socket) -> bool:
        data = chunk(c)
        if data is None:
            return False
        print("New message recieved")

        user_length, message = _split_header_message(data)

        user = pgp.pgp_decrypt(message[:user_length], self.private_key).decode()
        encrypted = message[user_length:]

        self.send_queue.get(user, []).append(encrypted)
        return True

    def send(self):
        for user, s in self.online.items():
            messages = self.send_queue.get(user, [])
            for m in messages:
                s.send(m)
            self.send_queue[user] = []

    def login(self, user_socket: socket.socket) -> tuple[str, bool]:
        random = urandom(8)
        user_socket.send(random + self.private_key.sign(random))
        received = user_socket.recv(1024)

        valid, username = _verify_login(random, received)
        if not valid:
            print("Invalid Login attempt:", username)
            return "", False
        self.online[username] = user_socket
        return username, True

    def logout(self, user_name: str):
        self.online.pop(user_name, None)


def _verify_login(random: bytes, received: bytes) -> tuple[bool, str]:
    certificate_len = received[:CERTIFICATE_LENGTH_BYTES]
    certificate_len = received[CERTIFICATE_LENGTH_BYTES:]
    username, pub_key = _split_certificate(received[:certificate_len])

    signature = received[certificate_len:]
    valid = pub_key.verify(random, signature)
    return valid, username


def _split_certificate(certificate: bytes) -> tuple[str, PublicKey]:
    # TODO: Properly split certificate into username and public key.
    #   For now, just assuming first byte is username length

    user_length = int.from_bytes(certificate[:1], "big")
    certificate[1:]
    user = certificate[:user_length].decode()

    public_key = public_key_from_bytes(certificate[user_length:])
    return user, public_key


def start(port=9999) -> Callable[[], None]:
    # AF_INET specifies IPV4, SOCK_STREAM specifies a TCP connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((socket.gethostname(), port))
    sock.listen()

    server = _Server(sock, load_private_key("server/private"))

    threading.Thread(target=_connect_thread, args=(server,)).start()
    threading.Thread(target=_send_thread, args=(server,)).start()

    def shutdown():
        server.shutdown = True

    return shutdown


def _connect_thread(server: _Server):
    while not server.shutdown:
        client, _ = server.sock.accept()
        threading.Thread(target=_receive_thread, args=(server, client, client)).start()


def _send_thread(server: _Server):
    while not server.shutdown:
        server.send()


def _receive_thread(server: _Server, username: str, client: socket.socket):
    username, open = server.login(client)
    open = True
    while open:
        open = server.receive(client)
        server.logout(username)


def _split_header_message(data: bytes) -> tuple[int, bytes]:
    user_length = int.from_bytes(data[:DEST_LENGTH_BYTES], "big")
    data = data[user_length:]
    message = data
    return user_length, message
