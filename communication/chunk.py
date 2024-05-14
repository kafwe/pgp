import socket
from log import log


def chunk(s: socket.socket) -> bytes | None:
    message: bytes = b""
    chunks = 0
    while True:
        chunk = s.recv(1024)
        if not chunk:
            return None
        chunks = chunks + 1
        message += chunk
        if len(chunk) < 1024:
            log(f"Chunking complete. Nothing remains: {len(chunk) == 0}")
            break
    log(f"Received {chunks} chunks.")
    return message
