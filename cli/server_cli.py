from cli.client_cli import auto_gen_keys
from communication.server import Server
from confidentiality.asymetric import PrivateKey, PublicKey, load_private_key
from log import log
from communication.mail_server import MailServer
from communication.ca_server import CAServer


def mail_server_cli():
    server = _start(9999, "server")
    if server is None:
        return
    assert isinstance(server, MailServer)
    server.start_sending()

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


def ca_server_cli():
    server = _start(9998, "ca")
    if server is None:
        return
    assert isinstance(server, CAServer)

    while True:
        print(
            """
Options:
    List Online Users(l)
    View Registered Users (v)
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
            # TODO: Get list of registerd users
            pass


def _start(default: int, type: str) -> Server | None:
    private_key = _load_key(type)

    port = default
    while True:
        try:
            if type == "server":
                server = MailServer.start(port, private_key)
            else:
                server = CAServer.start(port, private_key)
            break
        except Exception as e:
            try:
                log(str(e))
                print(
                    f"Unable to start server on port {port}."
                    "You are likely running a server on that port already."
                    "\nEnter an alternate port (WARNING: clients must connect with the chosen port.):\n"
                )
                p = input()
                if p == "":
                    return None
                port = int(p)
            except Exception:
                print(f"{port} is not a valid port")
    return server


def _load_key(username: str) -> PrivateKey | None:
    try:
        pri_key = load_private_key(f"{username}/private")
    except Exception as e:
        log(str(e))
        res = auto_gen_keys(username)
        if res is None:
            return None
        pri_key, _ = res
    return pri_key
