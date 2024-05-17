from log import log
import sqlite3
from datetime import datetime, timedelta
from confidentiality.asymetric import (
    PrivateKey,
    PublicKey,
    generate_key_pair,
    public_key_from_bytes,
)


class CertificateExpiredError(Exception):
    pass


class Certificate:
    def __init__(
        self,
        username: bytes,
        public_key: bytes,
        signature: bytes,
        creation_time: datetime | None = None,
        ttl_days: int = 365,
    ):
        self.username = username
        self.public_key = public_key
        self.signature = signature
        self.creation_time = creation_time or datetime.now()
        self.expiration_time = self.creation_time + timedelta(days=ttl_days)

    def serialize(self) -> bytes:
        return b"|".join(
            [
                self.username,
                self.public_key,
                self.signature,
                self.creation_time.isoformat().encode(),
                self.expiration_time.isoformat().encode(),
            ]
        )

    @classmethod
    def deserialize(cls, serialized_certificate: bytes) -> "Certificate":
        parts = serialized_certificate.split(b"|")
        log(f"Deserializing certificate = {serialized_certificate}")
        log(f"Parts = {parts}")
        username, public_key, signature, creation_time, expiration_time = parts
        return cls(
            username,
            public_key,
            signature,
            datetime.fromisoformat(creation_time.decode()),
            (
                datetime.fromisoformat(expiration_time.decode())
                - datetime.fromisoformat(creation_time.decode())
            ).days,
        )

    def print(self):
        print(f"Username: {self.username.decode()}")
        print(f"Public Key: {self.public_key}")
        print(f"Signature: {self.signature}")
        print(f"Creation Time: {self.creation_time}")
        print(f"Expiration Time: {self.expiration_time}")

    def is_valid(self, ca_public_key: PublicKey) -> bool:
        if datetime.now() > self.expiration_time:
            raise CertificateExpiredError("Certificate has expired.")

        data_to_verify = b"".join(
            [
                self.username,
                self.public_key,
                self.creation_time.isoformat().encode(),
                self.expiration_time.isoformat().encode(),
            ]
        )
        try:
            ca_public_key.verify(self.signature, data_to_verify)
            return True
        except Exception as e:
            return False

    def save(self, fileName):
        data = self.serialize()
        with open(f"keys/{fileName}", "wb") as file:
            file.write(data)

    def save_public_key(self, fileName: str):
        pub_key = public_key_from_bytes(self.public_key)
        print(f"Saved Public Key to keys/{fileName}")
        pub_key.save(fileName)


class CertificateAuthority:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(CertificateAuthority, cls).__new__(cls)
        return cls._instance

    def __init__(self, private_key: PrivateKey, db_path: str = "certificates.db"):
        if not hasattr(self, "initialized"):  # Ensures initialization happens only once
            self.private_key = private_key
            self.public_key = private_key.get_public_key()
            self.db_path = db_path
            self._initialize_db()
            self.initialized = True

    def _initialize_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    signature BLOB NOT NULL,
                    creation_time TEXT NOT NULL,
                    expiration_time TEXT NOT NULL
                )
            """
            )
            conn.commit()

    def generate_certificate(
        self, username: bytes, user_public_key: bytes, ttl_days: int = 365
    ) -> Certificate:
        if b"|" in username:
            raise ValueError("Username cannot contain the '|' character.")

        if username.decode() in [
            row[0]
            for row in sqlite3.connect(self.db_path)
            .cursor()
            .execute("SELECT username FROM certificates")
            .fetchall()
        ]:
            raise ValueError("Username already exists in the database.")

        creation_time = datetime.now()
        expiration_time = creation_time + timedelta(days=ttl_days)
        data_to_sign = b"".join(
            [
                username,
                user_public_key,
                creation_time.isoformat().encode(),
                expiration_time.isoformat().encode(),
            ]
        )
        signature = self.private_key.sign(data_to_sign)
        certificate = Certificate(
            username, user_public_key, signature, creation_time, ttl_days
        )

        self._store_certificate(certificate)
        return certificate

    def _store_certificate(self, certificate: Certificate):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO certificates (username, public_key, signature, creation_time, expiration_time)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    certificate.username.decode(),
                    certificate.public_key,
                    certificate.signature,
                    certificate.creation_time.isoformat(),
                    certificate.expiration_time.isoformat(),
                ),
            )
            conn.commit()

    def get_certificate(self, username: bytes) -> Certificate | None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT username, public_key, signature, creation_time, expiration_time
                FROM certificates
                WHERE username = ?
            """,
                (username,),
            )
            row = cursor.fetchone()
            if row:
                username, public_key, signature, creation_time, expiration_time = row
                return Certificate(
                    username,
                    public_key,
                    signature,
                    datetime.fromisoformat(creation_time),
                    (
                        datetime.fromisoformat(expiration_time)
                        - datetime.fromisoformat(creation_time)
                    ).days,
                )
            else:
                return None


def load_certificate(fileName: str) -> Certificate:
    with open(f"keys/{fileName}", "rb") as file:
        return Certificate.deserialize(file.read())
