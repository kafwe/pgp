from cryptography.hazmat.primitives.asymmetric import rsa


class KeyPair:
    private: rsa.RSAPrivateKey
    public: rsa.RSAPublicKey

    def __init__(self) -> None:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        self.private_key = private_key
        self.public_key = public_key
