import socket
from authenticity.certificate import Certificate, load_certificate as load
from communication.ca_server import apply_for_certificate, request_certificate
from confidentiality.asymetric import PrivateKey, PublicKey, public_key_from_bytes
from log import log


def load_certificate(private_key: PrivateKey, username: str) -> Certificate | None:
    try:
        cert = load(f"{username}/certificate")
        return cert
    except Exception as e:
        log(str(e))
        print(
            f"Unable to load Certificate for {username}. Would you like to request one from the CA Server? (y/n)"
        )
        choice = input()
        if choice == "y":
            ca = connect_ca()
            if ca is None:
                return None
            certificate = apply_for_certificate(
                ca, private_key.get_public_key(), username.encode()
            )
            if certificate is None:
                return
            print("Certificate Application succesful.")
            certificate.save(f"{username}/certificate")
            return certificate
        else:
            return None


def auto_request_certificate(
    ca_public_key: PublicKey, username: str, peer: str
) -> PublicKey | None:
    choice = input(
        f"You do not have {peer}'s public key saved. Request certificate from CA server? (y/n)\n"
    )
    if choice == "y":
        ca = connect_ca()
        if ca is None:
            return None
        cert = request_certificate(ca_public_key, ca, peer.encode())
        if cert is None:
            return None
        cert.save_public_key(f"{username}/{peer}")
        return public_key_from_bytes(cert.public_key)


def connect_ca() -> socket.socket | None:
    address = input("What is the CA server address? (default = localhost)\n")
    if address == "":
        address = None

    port = input("What is the CA server port? (default = 9998)\n")
    if port == "":
        port = int(9998)
    try:
        port = int(port)
    except Exception as e:
        log(str(e))
        print("Invalid port")
        return

    if address == "" or address is None:
        address = socket.gethostname()
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((address, port))
    except Exception as e:
        print(
            "Unable to connect to CA server. Are you sure that's the right address and port? Maybe the server is offline"
        )
        log(str(e))
    print("Connected Succesfully to the CA")
    return server
