import ecdsa
from Crypto.Hash import SHA3_256
from merkle_tree import merkleTree, check_auth_path
from rng import random_choice_solidity
from random import shuffle
from keccak256 import keccak_256, keccak_256_hash
import json


def gen_ECDSA_key():
    # sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1, hashfunc=keccak_256)
    # pk = sk.get_verifying_key()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex('dcd0df5687e2b31d17e8524deb2c5e1e42421d16a6a999d1a7f5d695c649dc1e'),
                                      curve=ecdsa.SECP256k1, hashfunc=keccak_256)
    pk = sk.get_verifying_key()
    return sk, pk


def token_verify(pk, sig, msg):
    # tkpk = ecdsa.VerifyingKey.from_string(pk, curve=ecdsa.SECP256k1, hashfunc=keccak_256)
    # assert tkpk.verify(sig, msg)
    return pk.verify(sig, msg)


class EthereumToken:
    def __init__(self):
        self.sk, self.pk = gen_ECDSA_key()

    def sign(self, msg):
        sig = self.sk.sign(msg, hashfunc=keccak_256)
        return sig


class EthereumTokenCluster:
    def __init__(self, n, mu, m):
        self.n = n
        self.mu = mu
        self.m = m
        self.sig = b'ECDSA-SECP256K1'
        self.tokens = [EthereumToken() for _ in range(1 << n)]
        self.merkleTree = merkleTree([t.pk.to_string() for t in self.tokens])
        self.merkleTree.check_tree_consistency()
        self.pp = (n, mu, m, self.sig)
        self.pk = self.merkleTree.root.val

    def sign(self, msg, solidity_format = False):
        # t = time.gmtime()
        kMain = SHA3_256.new(#bytes(str(t), encoding='UTF-8') +
                             bytes(str(self.pp), encoding='UTF-8') + self.pk + msg).digest()
        kPRG = SHA3_256.new(kMain + b'PRG').digest()
        kSIG = SHA3_256.new(kMain + b'SIG').digest()
        subset = random_choice_solidity(self.n, self.mu, kPRG)
        shuffle(subset)
        # signature = [t]
        signature = []
        for i in subset[0:self.m]:
            tk = self.tokens[i]
            auth_path = self.merkleTree.gen_auth_path(i)
            tkSig = tk.sign(kSIG)
            if not solidity_format:
                signature.append((i, tk.pk, auth_path, tkSig))
            else:
                signature.append({"idx": i,
                                  "pk": tk.pk.to_string().hex(),
                                  "proof": [b.hex() for b in auth_path[:-1]],
                                  "root": auth_path[-1].hex(),
                                  "r": tkSig.to_string().hex()[:64],
                                  "vs": tkSig.to_string().hex()[64:],
                                  })
        if not solidity_format:
            return signature
        else:
            return json.dumps(signature, indent=4)


def verify(msg, sig, pp, pk):
    # t = sig.pop(0)
    kMain = SHA3_256.new(#bytes(str(t), encoding='UTF-8') +
                         bytes(str(pp), encoding='UTF-8') + pk + msg).digest()
    kPRG = SHA3_256.new(kMain + b'PRG').digest()
    kSIG = SHA3_256.new(kMain + b'SIG').digest()
    n = pp[0]
    mu = pp[1]
    subset = random_choice_solidity(n, mu, kPRG)
    for s in sig:
        assert s[0] in subset
        assert check_auth_path(s[1].to_string(), s[2])
        assert token_verify(s[1], s[3], kSIG)
    return


if __name__ == '__main__':
    cluster = EthereumTokenCluster(10, 16, 8)
    msg = b'Hello World'
    signature = cluster.sign(msg)
    verify(msg, signature, cluster.pp, cluster.pk)
    print(cluster.sign(msg, solidity_format=True))

    # signature check
    # token = EthereumToken()
    # print(token.sk.to_string().hex())
    # print(token.pk.to_string().hex())
    # msg = b'Hello World!'
    # sig = token.sign(msg)
    # print(sig.hex()[:64])
    # print(sig.hex()[64:])

    # merkle proof check
    # cluster = EthereumTokenCluster(4, 1, 1)
    # idx = 5
    # print(cluster.tokens[idx].pk.to_string().hex())
    # for b in cluster.merkleTree.gen_auth_path(idx):
    #     print(b.hex())