from datetime import datetime
import socket

from authenticity.certificate import Certificate, CertificateAuthority
from communication.chunk import chunk
from communication.constants import (
    FROM_LENGTH_BYTES,
    CERT_APPLY_CODE,
    CERT_REQUEST_CODE,
)
from communication.server import Server
from confidentiality.asymetric import PrivateKey, PublicKey
from confidentiality.pgp import pgp_decrypt
from log import log


class CAServer(Server):
    ca: CertificateAuthority

    def __init__(self, sock: socket.socket, private_key: PrivateKey):
        super().__init__(sock, private_key)
        self.ca = CertificateAuthority(private_key)

    def receive(self, c: socket.socket) -> bool:
        data = chunk(c)
        if data is None:
            log("Received none. Assuming connection is closed.")
            return False

        log(f"Received {len(data)} bytes")
        code = data[:1]
        data = data[1:]
        if code == CERT_APPLY_CODE:
            message = self._handle_application(data)
        elif code == CERT_REQUEST_CODE:
            message = self._handle_request(data)
        else:
            log(str(code + data))
            print(f"Received invalid code: {code}. Closing connection to be safe.")
            return False

        c.send(message)
        return True

    def _handle_application(self, data: bytes) -> bytes:
        username_len = int.from_bytes(data[1:])
        username = data[:username_len]
        public_key = data[username_len:]
        try:
            self.ca.generate_certificate(username, public_key)
        except ValueError as e:
            print(e)
            log(str(e))
            return False.to_bytes()
        return True.to_bytes()

    def _handle_request(self, peer: bytes) -> bytes:
        cert = self.ca.get_certificate(peer)
        if cert is None:
            return False.to_bytes()
        return True.to_bytes() + cert.serialize()

    def login(self, user_socket: socket.socket):
        id = str(user_socket.getpeername()) + datetime.now().isoformat()
        self.online[id] = user_socket
        print(f"Succesful login attempt by socket: {user_socket}")
        return id, True


def request_certificate(
    ca_public_key: PublicKey, ca: socket.socket, peer: bytes
) -> Certificate | None:
    print(f"Requesting {peer.decode()}'s Certificate from CA.")
    try:
        ca.send(CERT_REQUEST_CODE + peer)
    except Exception as e:
        print("Connection to CA broken.")
        log(str(e))
        return None
    response = chunk(ca)
    if response is None:
        print("Unable to apply for certificate. Connection with CA closed.")
        return None
    print("Received response from CA")
    exists = bool.from_bytes(response[:1])
    if not exists:
        print("User has not registered with the CA.")
        return None

    cert = Certificate.deserialize(response[1:])
    if cert.is_valid(ca_public_key):
        print(f"Certificate for {peer} is valid.")
        return cert
    print("Received invalid certificate from CA. WARNING: CA may be compromised")
    return None


def apply_for_certificate(
    ca: socket.socket, public_key: PublicKey, username: bytes
) -> Certificate | None:
    len_username = len(username).to_bytes(FROM_LENGTH_BYTES)
    print("Sending application to CA.")
    ca.send(CERT_APPLY_CODE + len_username + username + public_key.to_bytes())
    response = chunk(ca)
    if response is None:
        print("Unable to apply for certificate. Connection with CA closed.")
        return None
    valid = bool.from_bytes(response[:1])
    if not valid:
        print("Username is already registered on the CA. Please try another one.")
        return None
    return Certificate.deserialize(response[1:])
