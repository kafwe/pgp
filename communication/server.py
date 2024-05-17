from abc import ABC, abstractmethod
from collections import defaultdict
import socket
import threading

from communication.mail_server import MailServer
from confidentiality.asymetric import PrivateKey, load_private_key
from log import log


class Server(ABC):
    online: dict[str, socket.socket]  # Username -> socket
    # TODO SAVE:
    sock: socket.socket
    isShutdown: bool = False

    def __init__(self, sock: socket.socket, private_key: PrivateKey):
        log("Initialising _Server object with private_key: server/private")
        self.private_key = private_key
        self.sock = sock
        log(f"Initalised sever socket: {sock}")
        self.online = {}

    @abstractmethod
    def receive(self, c: socket.socket):
        pass

    @abstractmethod
    def login(self, user_socket: socket.socket) -> tuple[str, bool]:
        pass

    def logout(self, user_name: str):
        # TODO: Add proper logout for users
        print(f"{user_name} has logged out")
        log(self.getOnline())
        self.online.pop(user_name, None)

    def getOnline(self) -> str:
        users: list[str] = list(self.online.keys())
        return f"{len(users)} users online:\n" + "\n".join(users)

    def shutdown(self):
        # TODO: Save messages
        self.isShutdown = True
        self.sock.shutdown(socket.SHUT_RDWR)
        sockets = list(self.online.values())
        for s in sockets:
            s.shutdown(socket.SHUT_RDWR)

    @classmethod
    def start(
        cls,
        port=9999,
    ) -> "Server":
        print(f"Starting TCP server at ip: {socket.gethostname()} port: {port}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((socket.gethostname(), port))
        sock.listen()
        log(f"Listening on socket: {sock}")

        server = cls(sock, load_private_key("ca/private"))
        log("Loaded server private key")

        threading.Thread(target=_connect_thread, args=(server,)).start()
        if isinstance(server, MailServer):
            threading.Thread(target=server.send_thread, args=(server,)).start()

        return server


def _connect_thread(server: Server):
    log("Server now accepting connections")
    while not server.isShutdown:
        try:
            log("Waiting for client...")
            client, address = server.sock.accept()
        except OSError:
            continue
        print(f"New client connected: {address}")
        threading.Thread(target=_receive_thread, args=(server, client, client)).start()
    log("Connect thread has shut down")


def _receive_thread(server: Server, username: str, client: socket.socket):
    log(f"Receive Thread for {username} active")
    username, open = server.login(client)
    open = True
    while open and not server.isShutdown:
        open = server.receive(client)
    server.logout(username)
    log(f"Continuing {username} thread. Open = {open} shutdown = {server.isShutdown}")
    log(f"Shutting down thread for {username}")
