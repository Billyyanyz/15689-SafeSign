import threading

from Crypto.Signature import eddsa
from Crypto.Hash import SHA3_256
from threading import Thread
from threading import Lock
from merkle_tree import merkleTree, check_auth_path
from rng import random_choice
from dsToken import Token, tokenVerify
import time


class TokenCluster:
    def __init__(self, n, mu, m):
        self.n = n
        self.mu = mu
        self.m = m
        self.sig = b'ECC-ed25519'
        self.tokens = [Token() for _ in range(pow(2, n))]
        self.merkleTree = merkleTree([t.pk.export_key(format='raw') for t in self.tokens])
        self.pp = (n, mu, m, self.sig)
        self.pk = self.merkleTree.root.val
        self.workload = [0] * pow(2, n)
        self.wLock = Lock()

    def refresh(self):
        newTokens = [Token() for _ in range(pow(2, self.n))]
        newMerkleTree = merkleTree([t.pk.export_key(format='raw') for t in newTokens])
        newPK = newMerkleTree.root.val
        agreeNum = 0
        for i in range(len(self.tokens)):
            sig = self.tokens[i].sign(newPK)
            if tokenVerify(eddsa.import_public_key(self.merkleTree.leaves[i].val), newPK, sig):
                agreeNum += 1
        if agreeNum >= pow(2, self.n - 1):
            self.tokens = newTokens
            self.merkleTree = newMerkleTree
            self.pk = newPK
            print('refresh success')
        else:
            print('refresh failed')

    def sign(self, msg):
        t = time.gmtime()
        kMain = SHA3_256.new(bytes(str(t), encoding='UTF-8')
                             + bytes(str(self.pp), encoding='UTF-8') + self.pk + msg).digest()
        kPRG = SHA3_256.new(kMain + b'PRG').digest()
        kSIG = SHA3_256.new(kMain + b'SIG').digest()
        subset = random_choice(self.n, self.mu, kPRG)

        with self.wLock:
            subset.sort(key=lambda x: self.workload[x])
            for i in subset[0:self.m]:
                self.workload[i] += 1

        signature = [t]
        for i in subset[0:self.m]:
            tk = self.tokens[i]
            signature.append((i, tk.pk, self.merkleTree.gen_auth_path(i), tk.sign(kSIG)))

        def update_workload(s):
            with self.wLock:
                for j in s[0:self.m]:
                    self.workload[j] -= 1

        timer = threading.Timer(1, update_workload, [subset])
        timer.start()
        return signature


def verify(msg, sig, pp, pk):
    t = sig.pop(0)
    kMain = SHA3_256.new(bytes(str(t), encoding='UTF-8')
                         + bytes(str(pp), encoding='UTF-8') + pk + msg).digest()
    kPRG = SHA3_256.new(kMain + b'PRG').digest()
    kSIG = SHA3_256.new(kMain + b'SIG').digest()
    n = pp[0]
    mu = pp[1]
    subset = random_choice(n, mu, kPRG)
    for s in sig:
        try:
            assert s[0] in subset
            leafVal = s[1].export_key(format='raw')
            check_auth_path(leafVal, s[2])
            verifier = eddsa.new(s[1], 'rfc8032')
            verifier.verify(kSIG, s[3])
        except Exception:
            return False
    return True


if __name__ == '__main__':
    cluster = TokenCluster(10, 16, 8)

    def req():
        msg = b'Hello World'
        signature = cluster.sign(msg)
        if not verify(msg, signature, cluster.pp, cluster.pk):
            raise AssertionError
        print('finish')

    threads = []
    for _ in range(40):
        thread = Thread(target=req)
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()

    cluster.refresh()
    #
    # threads = []
    # for _ in range(40):
    #     thread = Thread(target=req)
    #     threads.append(thread)
    #     thread.start()
    # for thread in threads:
    #     thread.join()
