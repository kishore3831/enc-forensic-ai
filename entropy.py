import math

def calculate_entropy(data):
    if not data:
        return 0

    entropy = 0
    length = len(data)

    for byte in set(data):
        p = data.count(byte) / length
        entropy -= p * math.log2(p)

    return entropy
