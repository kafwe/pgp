from log import log
from communication.server import Server, start as start_server


def server_cli():
    server = _start()
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


def _start() -> Server:
    port: int = 9999
    while True:
        try:
            server = start_server(port)
            break
        except Exception:
            try:
                request = f"Unable to start server on port {port}. You are likely running a server on that port already. \
                            \nEnter an alternate port (WARNING: clients must connect with the chosen port.):\n"
                port = int(input(request))
            except Exception:
                print(f"{port} is not a valid port")
    return server
