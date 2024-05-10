import json
import base64
from datetime import datetime, timedelta
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from confidentiality.asymetric import PublicKey, PrivateKey

class CertificateExpiredError(Exception):
    pass

class Certificate:
    def __init__(self, username: str, public_key: PublicKey, signature: bytes, ttl_days: int = 30):
        self.username = username
        self.public_key = public_key
        self.signature = signature
        self.creation_time = datetime.utcnow()
        self.expiration_time = self.creation_time + timedelta(days=ttl_days)

    @classmethod
    def generate(cls, username: str, user_public_key: PublicKey, ca_private_key: PrivateKey, ttl_days: int = 30) -> "Certificate":
        # Sign user's public key and username
        data_to_sign = username.encode()
        signature = ca_private_key.key.sign(
            data_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return cls(username, user_public_key, signature, ttl_days=ttl_days)

    def serialize(self) -> str:
        certificate_data = {
            "username": self.username,
            "public_key": self.public_key.key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode(),
            "signature": base64.b64encode(self.signature).decode(),
            "creation_time": self.creation_time.isoformat(),
            "expiration_time": self.expiration_time.isoformat()
        }
        return json.dumps(certificate_data)

    @classmethod
    def deserialize(cls, data: str) -> "Certificate":
        certificate_data = json.loads(data)
        username = certificate_data["username"]
        public_key = serialization.load_pem_public_key(
            certificate_data["public_key"].encode(),
        )
        signature = base64.b64decode(certificate_data["signature"])
        creation_time = datetime.fromisoformat(certificate_data["creation_time"])
        expiration_time = datetime.fromisoformat(certificate_data["expiration_time"])
        return cls(username, public_key, signature, creation_time, expiration_time)

    def verify(self, ca_public_key: PublicKey) -> bool:
        # Verify the signature
        data_to_verify = self.username.encode()
        try:
            ca_public_key.key.verify(
                self.signature,
                data_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            # Verify the certificate hasn't expired
            if datetime.utcnow() > self.expiration_time:
                raise CertificateExpiredError("Certificate has expired")
            return True
        except InvalidSignature:
            return False
