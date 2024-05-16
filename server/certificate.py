import sqlite3
from datetime import datetime, timedelta
from asymetric import PrivateKey, PublicKey, generate_key_pair

class CertificateExpiredError(Exception):
    pass


class Certificate:
    def __init__(self, username: bytes, public_key: bytes, signature: bytes, creation_time: datetime = None, ttl_days: int = 365):
        self.username = username
        self.public_key = public_key
        self.signature = signature
        self.creation_time = creation_time or datetime.now()
        self.expiration_time = self.creation_time + timedelta(days=ttl_days)

    def serialize(self) -> bytes:
        return b'|'.join([self.username, self.public_key, self.signature, self.creation_time.isoformat().encode(), self.expiration_time.isoformat().encode()])

    @classmethod
    def deserialize(cls, serialized_certificate: bytes) -> "Certificate":
        parts = serialized_certificate.split(b'|')
        username, public_key, signature, creation_time, expiration_time = parts
        return cls(username, public_key, signature, datetime.fromisoformat(creation_time.decode()), (datetime.fromisoformat(expiration_time.decode()) - datetime.fromisoformat(creation_time.decode())).days)

    def print(self):
        print(f"Username: {self.username.decode()}")
        print(f"Public Key: {self.public_key}")
        print(f"Signature: {self.signature}")
        print(f"Creation Time: {self.creation_time}")
        print(f"Expiration Time: {self.expiration_time}")

    def is_valid(self, ca_public_key: PublicKey, client_public_key: PublicKey) -> bool:
        if datetime.now() > self.expiration_time:
            raise ValueError("Certificate has expired.")
        
        data_to_verify = b''.join([self.username, self.public_key, self.creation_time.isoformat().encode(), self.expiration_time.isoformat().encode()])
        try:
            ca_public_key.verify(self.signature, data_to_verify)
            return True
        except Exception as e:
            return False

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
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    signature BLOB NOT NULL,
                    creation_time TEXT NOT NULL,
                    expiration_time TEXT NOT NULL
                )
            """)
            conn.commit()

    def generate_certificate(self, username: bytes, user_public_key: PublicKey, ttl_days: int = 365) -> Certificate:
        # check if username is in the database first and return an error if it is
        if username.decode() in [row[0] for row in sqlite3.connect(self.db_path).cursor().execute("SELECT username FROM certificates").fetchall()]:
            raise ValueError("Username already exists in the database.")

        creation_time = datetime.now()
        expiration_time = creation_time + timedelta(days=ttl_days)
        data_to_sign = b''.join([username.decode(), user_public_key, creation_time.isoformat().encode(), expiration_time.isoformat().encode()])
        signature = self.private_key.sign(data_to_sign)
        certificate = Certificate(username, user_public_key, signature, creation_time, ttl_days)
        
        self._store_certificate(certificate)
        return certificate

    def _store_certificate(self, certificate: Certificate):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO certificates (username, public_key, signature, creation_time, expiration_time)
                VALUES (?, ?, ?, ?, ?)
            """, (certificate.username, certificate.public_key, certificate.signature, certificate.creation_time.isoformat().encode(), certificate.expiration_time.isoformat().encode()))
            conn.commit()

    def get_certificate(self, username: bytes) -> Certificate:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT username, public_key, signature, creation_time, expiration_time
                FROM certificates
                WHERE username = ?
            """, (username,))
            row = cursor.fetchone()
            if row:
                username, public_key, signature, creation_time, expiration_time = row
                return Certificate(username, public_key, signature, datetime.fromisoformat(creation_time), (datetime.fromisoformat(expiration_time) - datetime.fromisoformat(creation_time)).days)
            else:
                return None

# Example usage
if __name__ == "__main__":
    private_key, _ = generate_key_pair()
    ca = CertificateAuthority(private_key)
    _, user_public_key = generate_key_pair()
    
    certificate = ca.generate_certificate(b"example_user", user_public_key)
    serialized_certificate = certificate.serialize()
    deserialized_certificate = Certificate.deserialize(serialized_certificate)
    
    deserialized_certificate.print()
    print("Certificate valid:", deserialized_certificate.is_valid(ca.public_key, user_public_key))
