from Crypto.Hash import keccak


class keccak_256:
    def __init__(self, data=b""):
        self._keccak = keccak.new(digest_bits=256)
        self.update(data)

    def update(self, data):
        self._keccak.update(data)

    def digest(self):
        return self._keccak.digest()

    def hexdigest(self):
        return self._keccak.hexdigest()


def keccak_256_hash(data):
    return keccak_256(data).digest()
