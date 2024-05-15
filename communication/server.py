import socket
import threading
from collections import defaultdict
from os import urandom
from typing import Callable

from log import log
import confidentiality.pgp as pgp
from communication.chunk import chunk
from communication.client import DEST_LENGTH_BYTES
from communication.fake_certificate import CERTIFICATE_LENGTH_BYTES
from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    load_private_key,
    public_key_from_bytes,
)

# class User:
#     username: str
#     ip: ststr


class _Server:
    private_key: PrivateKey
    online: dict[str, socket.socket]  # Username -> socket
    # Username -> list of messages to receive
    send_queue: dict[str, list[bytes]]
    sock: socket.socket
    shutdown = False

    def __init__(self, sock: socket.socket, private_key: PrivateKey):
        log("Initialising _Server object with private_key: server/private")
        self.private_key = private_key
        self.sock = sock
        log(f"Initalised sever socket: {sock}")
        self.online = {}
        self.send_queue = defaultdict(list)

    def receive(self, c: socket.socket) -> bool:
        data = chunk(c)
        if data is None:
            log("Received none. Assuming connection is closed.")
            return False

        user_length, message = _split_header_message(data)

        user = pgp.pgp_decrypt(message[:user_length], self.private_key).decode()
        encrypted = message[user_length:]
        print(f"New message recieved! Forwarding to user: {user}")

        self.send_queue.get(user, []).append(encrypted)
        return True

    def send(self):
        for user, s in self.online.items():
            messages = self.send_queue.get(user, [])
            if len(messages) == 0:
                continue
            print(f"Sending {len(messages)} messages to {user}")
            # TODO: Maybe require user to send acknowledgement
            for m in messages:
                s.send(m)
            self.send_queue[user] = []

    def login(self, user_socket: socket.socket) -> tuple[str, bool]:
        random = urandom(8)
        log(f"Login started. Generated random bytes: {int.from_bytes(random)}")
        signed = self.private_key.sign(random)
        log(f"Signed random and sending to user. Signature: {signed}")

        user_socket.send(random + signed)
        try:
            received = user_socket.recv(1024)
        except ConnectionResetError:
            return "", False
        log(f"Received response from user: {received}")

        valid, username = _verify_login(random, received)
        if not valid:
            print("Invalid Login attempt:", username)
            user_socket.send(False.to_bytes())
            return "", False
        self.online[username] = user_socket
        print(f"Succesful login attemp by user: {username}")
        log(f"Currently online: {self.getOnline()}")
        user_socket.send(True.to_bytes())
        return username, True

    def logout(self, user_name: str):
        # TODO: Add proper logout for users
        print(f"{user_name} has logged out")
        log(f"Currently online: {self.getOnline()}")
        self.online.pop(user_name, None)

    def getOnline(self) -> str:
        users: list[str] = list(self.online.keys())
        return ",".join(users)


def _verify_login(random: bytes, received: bytes) -> tuple[bool, str]:
    # TODO: Integrate with actual certificates
    certificate_len = int.from_bytes(received[:CERTIFICATE_LENGTH_BYTES])
    len(f"Verifying login with certificate of length: {certificate_len}")
    received = received[CERTIFICATE_LENGTH_BYTES:]
    username, pub_key = _split_certificate(received[:certificate_len])
    log(f"Received username: {username}")

    signature = received[certificate_len:]
    log(f"Received signature: {signature}")
    valid = pub_key.verify(random, signature)
    return valid, username


def _split_certificate(certificate: bytes) -> tuple[str, PublicKey]:
    # TODO: Properly split certificate into username and public key.
    #   For now, just assuming first byte is username length

    user_length = int.from_bytes(certificate[:1])
    certificate = certificate[1:]
    log(
        f"Splitting {user_length} from certificate: {certificate[:user_length + 10]}..."
    )
    user = certificate[:user_length].decode()
    log(f"Splitting certificate. User length: {user_length}. User: {user}")

    public_key = public_key_from_bytes(certificate[user_length:])
    return user, public_key


def start(port=9999) -> tuple[Callable[[], None], Callable[[], str]]:
    print(f"Starting TCP server at ip: {socket.gethostname()} port: {port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((socket.gethostname(), port))
    sock.listen()
    log(f"Listening on socket: {sock}")

    server = _Server(sock, load_private_key("server/private"))
    log("Loaded server private key")

    threading.Thread(target=_connect_thread, args=(server,)).start()
    threading.Thread(target=_send_thread, args=(server,)).start()

    def shutdown():
        server.shutdown = True
        server.sock.shutdown(socket.SHUT_RDWR)

    return shutdown, server.getOnline


def _connect_thread(server: _Server):
    log("Server now accepting connections")
    while not server.shutdown:
        try:
            log("Waiting for client...")
            client, address = server.sock.accept()
        except OSError:
            continue
        print(f"New client connected: {address}")
        threading.Thread(target=_receive_thread, args=(server, client, client)).start()
    log("Connect thread has shut down")


def _send_thread(server: _Server):
    log("Server send thread active")
    while not server.shutdown:
        server.send()
    log("Shutting down server send thread")


def _receive_thread(server: _Server, username: str, client: socket.socket):
    log(f"Receive Thread for {username} active")
    username, open = server.login(client)
    open = True
    while open and not server.shutdown:
        open = server.receive(client)
        server.logout(username)
    log(f"Shutting down thread for {username}")


def _split_header_message(data: bytes) -> tuple[int, bytes]:
    user_length = int.from_bytes(data[:DEST_LENGTH_BYTES])
    data = data[user_length:]
    message = data
    return user_length, message
