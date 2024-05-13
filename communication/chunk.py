import socket
from log import log


def chunk(c: socket.socket) -> bytes:
    message: bytes = b""
    while True:
        chunk = c.recv(1024)
        log(f"Chunk:{chunk}")
        message += chunk
        if len(chunk) < 1024:
            log("Returning")
            break
    return message
