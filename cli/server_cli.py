from log import log
from communication.server import start as start_server


def server_cli(port: int):
    server = start_server(port)
    while True:
        choice = input(
            """
Options:
    List Online Users(l)
    View Queued Messages(v)
    Quit (q)
        """
        )
        if choice == "q":
            log("Shutting down server")
            server.shutdown()
            break
        if choice == "l":
            print(server.getOnline())
        if choice == "v":
            print(server.getMessageQueue())
