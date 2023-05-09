import time
import threading

from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


def gen_ECC_key():
    sk = ECC.generate(curve='ed25519')
    pk = sk.public_key()
    return sk, pk


class Token:
    def __init__(self):
        self.sk, self.pk = gen_ECC_key()
        self.lastSigned = time.monotonic()

    def sign(self, msg):
        def _sign(s):
            if time.monotonic() < self.lastSigned + 1:
                self.lastSigned = self.lastSigned + 1
                time.sleep(self.lastSigned - time.monotonic())
            self.lastSigned = time.monotonic()
            signer = eddsa.new(self.sk, 'rfc8032')
            s['sig'] = signer.sign(msg)
            return
        s = {}
        t = threading.Thread(target=_sign, args=(s,))
        t.start()
        t.join()
        return s['sig']


def tokenVerify(pk, msg, sig):
    verifier = eddsa.new(pk, 'rfc8032')
    try:
        verifier.verify(msg, sig)
    except Exception:
        return False
    return True


if __name__ == "__main__":
    t = Token()
    for _ in range(10):
        sig = t.sign(b'Hello World!')
        print(sig)
        verifier = eddsa.new(t.pk, 'rfc8032')
        verifier.verify(b'Hello World!', sig)
