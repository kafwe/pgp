import zlib
import os
import socket
import threading
from datetime import datetime
from typing import Callable

from authenticity.certificate import Certificate, load_certificate
from communication import ca_server
import confidentiality.pgp as pgp
from communication.chunk import chunk
from communication.constants import (
    CAPTION_LENGTH_BYTES,
    CERT_REQUEST_CODE,
    CERTIFICATE_LENGTH_BYTES,
    DEST_LENGTH_BYTES,
    FROM_LENGTH_BYTES,
    SIG_LENGTH_BYTES,
    SUPPORTED_TYPES,
)
from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    load_private_key,
    load_public_key,
    load_public_key_bytes,
    public_key_from_bytes,
)
from log import log


class Client:
    private_key: PrivateKey
    server_socket: socket.socket
    server_public_key: PublicKey
    ca_public_key: PublicKey
    username: str
    certificate: Certificate
    isShutdown: bool

    def __init__(
        self,
        server_socket: socket.socket,
        private_key: PrivateKey,
        server_public_key: PublicKey,
        ca_public_key: PublicKey,
        username: str,
        certificate: Certificate,
    ):
        self.isShutdown = False
        self.private_key = private_key
        self.server_socket = server_socket
        self.server_public_key = server_public_key
        self.ca_public_key = ca_public_key
        log(f"Initialised user {username} with server public key: {server_public_key}")
        self.username = username
        self.certificate = certificate
        log(f"Initialised user {username} with certificate: {certificate}")

    def receive(self) -> bool:
        encrypted = chunk(self.server_socket)
        if encrypted is None:
            log("Received none. Assuming connection is closed.")
            return False
        log(f"Received {len(encrypted)} bytes")
        print("New message recieved!")

        decrypted = pgp.pgp_decrypt(encrypted, self.private_key)
        print("Decrypting...")
        if isinstance(decrypted, Exception):
            print(
                "ERROR: Unable to decrypt image. Peer may have incorrect public key."
                " It is recommended that you resend your certificate to them."
            )
            log(str(decrypted))
            return True
        print("Decompressing...")
        decompressed = zlib.decompress(decrypted)
        _receive_image(decompressed, self.username)
        return True

    # def request_certificate(self, peer: str):
    #     dest = peer.encode()
    #     log(f"Requesting certificate from {peer} = {dest}")
    #     encrypted_dest = pgp.pgp_encrypt(dest, self.server_public_key)
    #     dest_len = len(encrypted_dest).to_bytes(DEST_LENGTH_BYTES)
    #     to_send = dest_len + encrypted_dest + CERT_REQUEST_CODE + self.username.encode()
    #     log(f"Sending {len(to_send)} bytes")
    #     self.server_socket.send(to_send)

    # def send_certificate(self, peer: str):
    #     print(f"Sending certificate to {peer}")
    #     dest = peer.encode()
    #     encrypted_dest = pgp.pgp_encrypt(dest, self.server_public_key)
    #     dest_len = len(encrypted_dest).to_bytes(DEST_LENGTH_BYTES)
    #     log(f"Sending certificate. dest_len = {dest_len}")
    #     self.server_socket.send(
    #         dest_len + encrypted_dest + CERT_RESPONSE_CODE + self.certificate
    #     )

    def send_image(
        self,
        peer_username: str,
        peer_public_key: PublicKey,
        image: bytes,
        file_type: str,
        caption: str,
    ):
        header = _create_header(self.username, file_type, caption)
        compressed = zlib.compress(header + image)
        encrypted = pgp.pgp_encrypt(compressed, peer_public_key)

        dest_bytes = peer_username.encode()
        dest_encrypted = pgp.pgp_encrypt(dest_bytes, self.server_public_key)
        dest_len = len(dest_encrypted).to_bytes(DEST_LENGTH_BYTES)
        # Send packet to reciever
        self.server_socket.send(dest_len + dest_encrypted + encrypted)
        print("Message sent")

    def login(self) -> bool:
        print("Logging in...")
        received = self.server_socket.recv(1024)
        if received is None:
            print("Server is no longer online. Shutting down...")
            return False
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
        cert = self.certificate.serialize()
        cert_len = int.to_bytes(len(cert), CERTIFICATE_LENGTH_BYTES)
        log(f"Sending certificate of length: {cert_len}")
        msg = cert_len + cert + my_sig
        self.server_socket.send(msg)
        log("Sending login request to server")

        valid = bool.from_bytes(self.server_socket.recv(1024))
        log(f"Received respnonse: {valid}")
        if not valid:
            print("Login rejected. Are you using a valid certificate?")
        return valid

    def shutdown(self):
        self.isShutdown = True
        self.server_socket.shutdown(socket.SHUT_RDWR)


def _create_header(sender: str, file_type: str, caption: str) -> bytes:
    encoded_caption = caption.encode()
    encoded_sender = sender.encode()
    encoded_file_type = file_type.encode()
    caption_len = len(encoded_caption).to_bytes(CAPTION_LENGTH_BYTES)
    from_length = len(encoded_sender).to_bytes(FROM_LENGTH_BYTES)
    file_type_len = len(encoded_file_type).to_bytes(1)

    log(f"From is of length: {from_length}")
    return (
        caption_len
        + from_length
        + file_type_len
        + encoded_caption
        + encoded_sender
        + encoded_file_type
    )


def _split_header_message(data: bytes) -> tuple[int, int, int, bytes]:
    # TODO: Add certificate
    # TODO: Error handling for caption that is too large
    # TODO: Add MAC?
    caption_length = int.from_bytes(data[:CAPTION_LENGTH_BYTES])
    log(f"Caption is of length {caption_length}")
    data = data[CAPTION_LENGTH_BYTES:]

    from_length = int.from_bytes(data[:FROM_LENGTH_BYTES])
    log(f"SEnder is of length {from_length}")
    data = data[FROM_LENGTH_BYTES:]

    file_type_length = int.from_bytes(data[:1])
    log(f"Sender is of length {from_length}")
    data = data[1:]

    message = data
    log(f"Message data is of length {len(message)}")

    return caption_length, from_length, file_type_length, message


def _save_image(
    image_data: bytes, username: str, sender: str, caption: str, file_type: str
):
    dir = f"images/{username}"
    if not os.path.exists(dir):
        os.makedirs(dir)
    date_time = datetime.now().strftime("%Y-%m-%d--%H:%M:%S")
    if len(caption) > 30:
        caption = caption[:30]
    file_name = f"{date_time}--{sender}--{caption}"

    if file_type not in SUPPORTED_TYPES:
        print(
            f"WARNING: Received unsupported file type: {file_type} from sender. Discarding."
        )
    with open(f"images/{username}/{file_name}.{file_type}", "wb") as file:
        file.write(image_data)

    print(f"Image saved as {file_name}")


def start(
    username: str,
    private_key: PrivateKey,
    certificate: Certificate,
    server_public_key: PublicKey,
    ca_public_key: PublicKey,
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

    client = Client(
        server, private_key, server_public_key, ca_public_key, username, certificate
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


def _receive_image(decrypted: bytes, username: str) -> bool:
    caption_length, from_length, file_type_length, message = _split_header_message(
        decrypted
    )
    log(f"From is of length: {from_length}")

    caption = message[:caption_length].decode()
    message = message[caption_length:]
    sender = message[:from_length]
    message = message[from_length:]
    file_type = message[:file_type_length]
    image = message[file_type_length:]

    print(f"Received Image from: {sender}")
    print(f"Image caption: {caption}")
    _save_image(image, username, sender.decode(), caption, file_type.decode())
    return True
