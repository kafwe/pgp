import socket
import threading
from collections import defaultdict
from os import urandom

from authenticity.certificate import Certificate
from communication.constants import CERTIFICATE_LENGTH_BYTES
from communication.server import Server
from log import log
import confidentiality.pgp as pgp
from communication.chunk import chunk
from communication.client import DEST_LENGTH_BYTES
from confidentiality.asymetric import (
    PrivateKey,
    load_public_key,
    public_key_from_bytes,
)

# class User:
#     username: str
#     ip: ststr


class MailServer(Server):
    send_queue: dict[str, list[bytes]]

    def __init__(self, sock: socket.socket, private_key: PrivateKey):
        super().__init__(sock, private_key)
        self.send_queue = defaultdict(list)

    def receive(self, c: socket.socket) -> bool:
        data = chunk(c)
        if data is None:
            log("Received none. Assuming connection is closed.")
            return False

        log(f"Received {len(data)} bytes")
        split = self._split_dest_message(data)
        if split is None:
            return True
        user, message = split
        print(f"New message recieved! Forwarding to user: {user}")

        sq = self.send_queue.get(user)
        if sq is None:
            sq = []
        sq.append(message)
        self.send_queue[user] = sq
        return True

    def _split_dest_message(self, data: bytes) -> tuple[str, bytes] | None:
        dest_length = int.from_bytes(data[:DEST_LENGTH_BYTES])
        log(f"Splitting destination from message. dest_length: {dest_length}")
        data = data[DEST_LENGTH_BYTES:]

        dest_encrypted = data[:dest_length]
        data = data[dest_length:]

        log(f"Decrypting dest: {dest_encrypted}")
        dest = pgp.pgp_decrypt(dest_encrypted, self.private_key)
        if isinstance(dest, Exception):
            print(
                "Unable to decrypt destination. User is likely using the incorrect server public key."
            )
            log(str(dest))
            return None
        dest = bytes(dest)
        log(f"Decrypted dest: {dest}/{dest.decode()}")
        return dest.decode(), data

    def login(self, user_socket: socket.socket) -> tuple[str, bool]:
        random = urandom(8)
        log(f"Login started. Generated random bytes: {int.from_bytes(random)}")
        signed = self.private_key.sign(random)
        log("Signed random and sending to user")

        user_socket.send(random + signed)
        try:
            received = chunk(user_socket)
            if received is None:
                raise ConnectionResetError
        except ConnectionResetError:
            return "", False

        valid, username = _verify_login(random, received)
        if not valid:
            print("Invalid Login attempt:", username)
            user_socket.send(False.to_bytes())
            return "", False
        self.online[username] = user_socket
        print(f"Succesful login attempt by user: {username}")
        log(self.getOnline())
        user_socket.send(True.to_bytes())
        return username, True

    def send(self):
        users = list(self.online.items())
        for user, s in users:
            messages = self.send_queue.get(user, [])
            if len(messages) == 0:
                continue
            print(f"Sending {len(messages)} messages to {user}")
            for m in messages:
                s.send(m)
            self.send_queue[user] = []

    def getMessageQueue(self) -> str:
        s: str = "Message Queue:\n"
        try:
            send_queue = self.send_queue.items()
            for user, messages in send_queue:
                if len(messages) == 0:
                    s += f"{len(messages)} messages for {user}\n"
            return s
        except Exception:
            return "ERROR: messages modified while reading. Please try again."

    def send_thread(self):
        log("Server send thread active")
        while not self.isShutdown:
            self.send()
        log("Shutting down server send thread")

    def start_sending(self):
        threading.Thread(target=self.send_thread, args=()).start()


def _verify_login(random: bytes, received: bytes) -> tuple[bool, str]:
    # TODO: Integrate with actual certificates
    certificate_len = int.from_bytes(received[:CERTIFICATE_LENGTH_BYTES])
    len(f"Verifying login with certificate of length: {certificate_len}")
    received = received[CERTIFICATE_LENGTH_BYTES:]
    cert = Certificate.deserialize(received[:certificate_len])
    log("received certificate")
    public_key = public_key_from_bytes(cert.public_key)
    log(f"Received username: {cert.username.decode()}")

    signature = received[certificate_len:]
    log(f"Received signature of length {len(signature)}")
    valid_certificate = cert.is_valid(load_public_key("ca_public_key"))
    log(f"Invalid certificate for {cert.username.decode()}")
    valid_signature = public_key.verify(random, signature)
    log(f"Invalid signature for {cert.username.decode()}")
    return valid_signature and valid_certificate, cert.username.decode()
