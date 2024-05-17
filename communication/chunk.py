import socket
from log import log


def chunk(s: socket.socket, num_chunks: int | None = None) -> bytes | None:
    message: bytes = b""
    chunks = 0
    chunk = b""
    while True:
        log("Received chunk")
        chunk = s.recv(1024)
        if not chunk:
            return None
        chunks = chunks + 1
        message += chunk
        if len(chunk) < 1024:
            if num_chunks is not None and chunks < num_chunks:
                continue
            break
    log(f"Received {chunks} chunks.")
    return message
