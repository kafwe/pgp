import socket


def start_server() -> socket.socket:
    # AF_INET specifies IPV4, SOCK_STREAM specifies a TCP connection
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((socket.gethostname(), 9999))
    server.listen()
    client, _ = server.accept()
    return client


def start_client(ip_address: str = socket.gethostname()) -> socket.socket:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip_address, 9999))
    return client
