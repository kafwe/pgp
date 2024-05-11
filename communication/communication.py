import socket


def start_server(port=9999) -> socket.socket:
    # AF_INET specifies IPV4, SOCK_STREAM specifies a TCP connection
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((socket.gethostname(), port))
    server.listen()
    client, _ = server.accept()
    return client


def start_client(port=9999, ip_address: str = socket.gethostname()) -> socket.socket:
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip_address, port))
    return client
