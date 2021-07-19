import random

def decrypt(message, key):
    random.seed(key)
    l = list(range(len(message)))
    random.shuffle(l)
    return "".join(message[i] for i, x in sorted(enumerate(l), key=lambda x: x[1]))

for i in range(0, 1000):
    print(decrypt('zftr}__g5y_ee0y1{graua00n1l', i))
