import random
from numpy.random import Generator
from randomgen import ChaCha
from keccak256 import keccak_256_hash


# choosing mm out of range(2^n), based on seed
def random_choice_naive(n, mm, seed):
    choice = []
    random.seed(seed)
    while len(choice) < mm:
        r = random.randrange(pow(2, n))
        if r not in choice:
            choice.append(r)
    return choice


# use chacha for random
def random_choice(n, mm, seed: bytes):
    rg = Generator(ChaCha(list(seed)))
    choice = rg.choice(pow(2, n), mm, replace=False)
    return choice


def random_choice_solidity(n, mm, seed: bytes):
    choice = []
    iter = 0
    out = bytes(32)
    while len(choice) < mm:
        out = keccak_256_hash(seed + str(iter).encode('UTF-8') + out)
        iter += 1
        randomInts = int.from_bytes(out, 'big')
        while (randomInts >= (1 << n)) and len(choice) < mm:
            c = randomInts & ((1 << n) - 1)
            randomInts = randomInts >> n
            if c not in choice:
                choice.append(c)
    return choice


if __name__ == "__main__":
    b = keccak_256_hash(b'Hello World!')
    print(b.hex())
    print(random_choice_solidity(10, 5, b))
