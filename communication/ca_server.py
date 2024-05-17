from datetime import datetime
import socket

from authenticity.certificate import CertificateAuthority
from communication.chunk import chunk
from communication.server import Server
from confidentiality.asymetric import PrivateKey
from confidentiality.pgp import pgp_decrypt
from log import log

CERT_APPLY_CODE = False.to_bytes()
CERT_REQUEST_CODE = True.to_bytes()


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
        code = data[0]
        data = data[1:]
        if code == CERT_APPLY_CODE:
            message = self._handle_application(data)
        if code == CERT_REQUEST_CODE:
            message = self._handle_request(data)

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
        self.online[str(user_socket.getpeername()) + datetime.now().isoformat()] = (
            user_socket
        )
        print(f"Succesful login attempt by socket: {user_socket}")
