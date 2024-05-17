CERTIFICATE_LENGTH_BYTES = 4
#
# Number of bytes dedicated to stating the caption's length
CAPTION_LENGTH_BYTES = 2  # Max size = ~65536 characters
# Number of bytes dedicated to stating the destination username length
DEST_LENGTH_BYTES = 4  # Note: Destination is encrypted
# Number of bytes dedicated to stating the sender's username length
FROM_LENGTH_BYTES = 1  # Max size = 256 characters

CERT_APPLY_CODE = False.to_bytes()
CERT_REQUEST_CODE = True.to_bytes()

SUPPORTED_TYPES = ["jpg", "jpeg", "png", "pdf", "svg"]
