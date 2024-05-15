import socket
import threading
from datetime import datetime
from typing import Callable

import confidentiality.pgp as pgp
from communication.chunk import chunk
from communication.fake_certificate import CERTIFICATE_LENGTH_BYTES, split_certificate
from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    load_private_key,
    load_public_key,
    load_public_key_bytes,
)
from log import log

# Number of bytes dedicated to stating the caption's length
CAPTION_LENGTH_BYTES = 2  # Max size = ~65536 characters
# Number of bytes dedicated to stating the destination username length
DEST_LENGTH_BYTES = 4  # Note: Destination is encrypted
# Number of bytes dedicated to stating the sender's username length
FROM_LENGTH_BYTES = 1  # Max size = 256 characters

IMAGE_CODE = (0).to_bytes(1)
CERT_REQUEST_CODE = (1).to_bytes(1)
CERT_RESPONSE_CODE = (2).to_bytes(1)


class Client:
    private_key: PrivateKey
    server_socket: socket.socket
    server_public_key: PublicKey
    username: str
    certificate: bytes

    def __init__(
        self,
        server_socket: socket.socket,
        private_key: PrivateKey,
        server_public_key: PublicKey,
        username: str,
        certificate: bytes,
    ):
        self.private_key = private_key
        self.server_socket = server_socket
        self.server_public_key = server_public_key
        log(f"Initialised user {username} with server public key: {server_public_key}")
        self.username = username
        self.certificate = certificate
        log(f"Initialised user {username} with certificate: {certificate}")

    def receive(self) -> bool:
        data = chunk(self.server_socket)
        if data is None:
            log("Received none. Assuming connection is closed.")
            return False
        log(f"Received {len(data)} bytes")
        print("New message recieved!")

        code = data[:1]
        data = data[1:]
        log(f"Receive message code: {code}")
        if code == IMAGE_CODE:
            encrypted = data
            decrypted = pgp.pgp_decrypt(encrypted, self.private_key)
            _receive_image(decrypted)
        elif code == CERT_REQUEST_CODE:
            peer = data.decode()
            print(f"Received certificate request from {peer}")
            self.send_certificate(data.decode())
        elif code == CERT_RESPONSE_CODE:
            peer, key = split_certificate(data)
            print(f"Received certificate from {peer}.")
            # TODO Verify Certificate
            path = f"{self.username}/{peer}"
            print(f"Saving {peer}'s public key: keys/{path}")
            key.save(path)
        return True

    def request_certificate(self, peer: str):
        dest = peer.encode()
        log(f"Requesting certificate from {peer} = {dest}")
        encrypted_dest = pgp.pgp_encrypt(dest, self.server_public_key)
        log(f"Encrypted dest = {encrypted_dest}")
        log(f"Decrypted dest = {testDecrypt(encrypted_dest)}")
        dest_len = len(encrypted_dest).to_bytes(DEST_LENGTH_BYTES)
        log(f"Requesting certificate. dest_len = {len(encrypted_dest)}")
        to_send = dest_len + encrypted_dest + CERT_REQUEST_CODE + self.username.encode()
        log(f"Sending {len(to_send)} bytes")
        self.server_socket.send(to_send)

    def send_certificate(self, peer: str):
        print(f"Sending certificate to {peer}")
        dest = peer.encode()
        encrypted_dest = pgp.pgp_encrypt(dest, self.server_public_key)
        dest_len = len(encrypted_dest).to_bytes(DEST_LENGTH_BYTES)
        log(f"Sending certificate. dest_len = {dest_len}")
        self.server_socket.send(
            dest_len + encrypted_dest + CERT_RESPONSE_CODE + self.certificate
        )

    def send_image(
        self, peer_username: str, peer_public_key: PublicKey, image: bytes, caption: str
    ):
        header = _create_header(self.username, caption)
        encrypted = pgp.pgp_encrypt(header + image, peer_public_key)

        dest_bytes = peer_username.encode()
        dest_encrypted = pgp.pgp_encrypt(dest_bytes, self.server_public_key)
        dest_len = len(dest_encrypted).to_bytes(DEST_LENGTH_BYTES)
        # Send packet to reciever
        self.server_socket.send(dest_len + dest_encrypted + IMAGE_CODE + encrypted)
        print("Message sent")

    def login(self) -> bool:
        print("Logging in")
        received = self.server_socket.recv(1024)
        random = received[:8]
        sig = received[8:]
        log(
            f"Received {len(received)} bytes. Random: {int.from_bytes(random)} and sig of length: {len(sig)}"
        )
        valid = self.server_public_key.verify(random, sig)
        if not valid:
            print("WARNING: Server is compramised. Invalid signature.")
            return False

        my_sig = self.private_key.sign(random)
        log(f"My signature (signed the random) is of length: {len(my_sig)}")
        cert_len = int.to_bytes(len(self.certificate), CERTIFICATE_LENGTH_BYTES)
        log(f"Sending certificate of length: {cert_len}")
        msg = cert_len + self.certificate + my_sig
        self.server_socket.send(msg)
        log("Sending login request to server")

        valid = bool.from_bytes(self.server_socket.recv(1024))
        log(f"Received respnonse: {valid}")
        if not valid:
            print("Login rejected. Are you using a valid certificate?")
        return valid


def _create_header(sender: str, caption: str) -> bytes:
    # TODO: Error handling for caption that is too large
    # TODO: Add MAC?
    # TODO: Add certificate
    encoded_caption = caption.encode()
    encoded_sender = sender.encode()
    caption_len = len(encoded_caption).to_bytes(CAPTION_LENGTH_BYTES)
    from_length = len(encoded_sender).to_bytes(FROM_LENGTH_BYTES)

    log(f"From is of length: {from_length}")
    return caption_len + from_length + encoded_caption + encoded_sender


def _split_header_message(data: bytes) -> tuple[int, int, bytes]:
    # TODO: Add certificate
    # TODO: Error handling for caption that is too large
    # TODO: Add MAC?
    caption_length = int.from_bytes(data[:CAPTION_LENGTH_BYTES])
    log(f"Caption is of length {caption_length}")
    data = data[CAPTION_LENGTH_BYTES:]

    from_length = int.from_bytes(data[:FROM_LENGTH_BYTES])
    log(f"SEnder is of length {from_length}")
    data = data[FROM_LENGTH_BYTES:]

    message = data
    log(f"Message data is of length {len(message)}")

    return caption_length, from_length, message


def _save_image(image_data: bytes, sender: str, caption: str):
    date_time = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    file_name = f"{date_time}--{sender}--{caption}"

    with open(f"images/{file_name}", "wb") as file:
        file.write(image_data)

    print(f"Image saved as {file_name}")


def start(
    username: str,
    server_address: str | None,
    server_port=9999,
) -> Client:
    print(
        f"Starting TCP connection to server at ip: {server_address} port: {server_port}"
    )
    if server_address == "" or server_address is None:
        server_address = socket.gethostname()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.connect((server_address, server_port))
    user = username.encode()
    user_len = len(user).to_bytes(1)

    pri_key = load_private_key(f"{username}/private")
    server_pub_key = load_public_key("server/public")
    log("Succesfully loaded private and public keys")

    client = Client(
        server,
        pri_key,
        server_pub_key,
        username,
        user_len + user + load_public_key_bytes(f"{username}/public"),
    )

    threading.Thread(target=_receive_thread, args=(client,)).start()
    return client


def _receive_thread(client: Client):
    open = client.login()
    if open:
        log("Now receiving messages")
    while open:
        log("Waiting for messages...")
        open = client.receive()


def _receive_image(decrypted: bytes):
    caption_length, from_length, message = _split_header_message(decrypted)
    log(f"From is of length: {from_length}")

    caption = message[:caption_length].decode()
    message = message[caption_length:]
    sender = message[:from_length]
    image = message[from_length:]

    print(f"From: {sender}")
    print(f"Image caption: {caption}")
    # TODO: Give the user an option to choose file_name
    _save_image(image, sender.decode(), caption)
    return True


def testDecrypt(data: bytes) -> bytes:
    pri_key = load_private_key("server/private")
    log(f"Loaded pri_key + {pri_key}")
    return pgp.pgp_decrypt(data, pri_key)
