import argparse
import sys

# SHA-2.py
def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def _shr(x, n):
    return x >> n

# SHA-256 constants
K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    # Preprocessing
    orig_len_bits = (8 * len(data)) & 0xffffffffffffffff
    data += b'\x80'
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'
    data += orig_len_bits.to_bytes(8, byteorder='big')

    # Initial hash values
    H = [
        0x6a09e667, 0xbb67ae85,
        0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    ]

    for chunk_offset in range(0, len(data), 64):
        chunk = data[chunk_offset:chunk_offset+64]
        w = [int.from_bytes(chunk[i:i+4], 'big') for i in range(0, 64, 4)]
        for t in range(16, 64):
            s0 = (_rotr(w[t-15], 7) ^ _rotr(w[t-15], 18) ^ _shr(w[t-15], 3)) & 0xFFFFFFFF
            s1 = (_rotr(w[t-2], 17) ^ _rotr(w[t-2], 19) ^ _shr(w[t-2], 10)) & 0xFFFFFFFF
            val = (w[t-16] + s0 + w[t-7] + s1) & 0xFFFFFFFF
            w.append(val)

        a,b,c,d,e,f,g,h = H

        for t in range(64):
            S1 = (_rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)) & 0xFFFFFFFF
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + K256[t] + w[t]) & 0xFFFFFFFF
            S0 = (_rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)) & 0xFFFFFFFF
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        H = [
            (H[0] + a) & 0xFFFFFFFF,
            (H[1] + b) & 0xFFFFFFFF,
            (H[2] + c) & 0xFFFFFFFF,
            (H[3] + d) & 0xFFFFFFFF,
            (H[4] + e) & 0xFFFFFFFF,
            (H[5] + f) & 0xFFFFFFFF,
            (H[6] + g) & 0xFFFFFFFF,
            (H[7] + h) & 0xFFFFFFFF
        ]

    digest = b''.join(x.to_bytes(4, 'big') for x in H)
    return digest.hex()

# Convenience wrappers
def sha256_of_string(s: str) -> str:
    return sha256(s)


def sha256_of_file(path: str) -> str:
    with open(path, 'rb') as f:
        data = f.read()
    return sha256(data)


# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute SHA-256 hash of a string or file.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--string', help='String to hash')
    group.add_argument('-f', '--file', help='File to hash')
    args = parser.parse_args()

    if args.string is not None:
        digest = sha256_of_string(args.string)
        print(f"SHA-256 (string): {digest}")
    else:
        try:
            digest = sha256_of_file(args.file)
            print(f"SHA-256 (file): {digest}")
        except FileNotFoundError:
            print(f"File not found: {args.file}", file=sys.stderr)
            sys.exit(2)