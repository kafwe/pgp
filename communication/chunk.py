import socket
from log import log


def chunk(s: socket.socket) -> bytes | None:
    message: bytes = b""
    while True:
        chunk = s.recv(1024)
        if not chunk:
            return None
        log(f"Chunk:{chunk}")
        message += chunk
        if len(chunk) < 1024:
            log("Returning")
            break
    return message
