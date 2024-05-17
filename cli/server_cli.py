from log import log
from communication.mail_server import MailServer, start as start_server


def server_cli():
    server = _start()
    if server is None:
        return

    while True:
        print(
            """
Options:
    List Online Users(l)
    View Queued Messages(v)
    Quit (q)
        """
        )
        choice = input()
        if choice == "q":
            log("Shutting down server")
            server.shutdown()
            break
        if choice == "l":
            print(server.getOnline())
        if choice == "v":
            print(server.getMessageQueue())


def _start() -> MailServer | None:
    port: int = 9999
    while True:
        try:
            server = start_server(port)
            break
        except Exception:
            try:
                request = f"Unable to start server on port {port}. You are likely running a server on that port already. \
                            \nEnter an alternate port (WARNING: clients must connect with the chosen port.):\n"
                p = input(request)
                if p == "":
                    return None
                port = int(p)
            except Exception:
                print(f"{port} is not a valid port")
    return server
