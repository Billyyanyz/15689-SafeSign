# Simple throughput test
from random import sample, seed
from Crypto.Hash import SHA3_256

n = 1 << 12
m = 8
mm = 16
# s = 1

trial = 1000


if __name__ == "__main__":
    res = []
    for s in range(1, 202, 4):
        dist = [0] * (s + 1)
        for i in range(trial):
            load = [0] * n
            for j in range(s):
                seed(SHA3_256.new(b'Billy' + str(1809 + i * trial + j).encode('utf-8') + b'Yan').digest())
                token_subset = sample(range(n), mm)
                token_subset.sort(key=lambda x: load[x])
                for k in token_subset[0:m]:
                    load[k] += 1
            dist[max(load)] += 1
            # print()

        print(s, "||")
        for i in range(s + 1):
            if dist[i] != 0:
                print(i, ":", dist[i])
        print()
        res.append(dist[1])
        print(res)


