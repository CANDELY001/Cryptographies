# SHA-512.py
import argparse
import sys

def _rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def _shr64(x, n):
    return x >> n

K512 = [
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]

def sha512(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    orig_len_bits = (8 * len(data)) & 0xffffffffffffffff
    data += b'\x80'
    while (len(data) * 8) % 1024 != 896:
        data += b'\x00'
    data += orig_len_bits.to_bytes(8, 'big')  # for messages < 2^64 bits this is fine, spec actually allows 128-bit length

    # initial hash values (first 64 bits of the fractional parts of the square roots of the first 8 primes)
    H = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ]

    for chunk_offset in range(0, len(data), 128):
        chunk = data[chunk_offset:chunk_offset+128]
        w = [int.from_bytes(chunk[i:i+8], 'big') for i in range(0, 128, 8)]
        for t in range(16, 80):
            s0 = (_rotr64(w[t-15], 1) ^ _rotr64(w[t-15], 8) ^ _shr64(w[t-15], 7)) & 0xFFFFFFFFFFFFFFFF
            s1 = (_rotr64(w[t-2], 19) ^ _rotr64(w[t-2], 61) ^ _shr64(w[t-2], 6)) & 0xFFFFFFFFFFFFFFFF
            val = (w[t-16] + s0 + w[t-7] + s1) & 0xFFFFFFFFFFFFFFFF
            w.append(val)

        a,b,c,d,e,f,g,h = H

        for t in range(80):
            S1 = (_rotr64(e,14) ^ _rotr64(e,18) ^ _rotr64(e,41)) & 0xFFFFFFFFFFFFFFFF
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + K512[t] + w[t]) & 0xFFFFFFFFFFFFFFFF
            S0 = (_rotr64(a,28) ^ _rotr64(a,34) ^ _rotr64(a,39)) & 0xFFFFFFFFFFFFFFFF
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFFFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFFFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFFFFFFFFFF

        H = [
            (H[0] + a) & 0xFFFFFFFFFFFFFFFF,
            (H[1] + b) & 0xFFFFFFFFFFFFFFFF,
            (H[2] + c) & 0xFFFFFFFFFFFFFFFF,
            (H[3] + d) & 0xFFFFFFFFFFFFFFFF,
            (H[4] + e) & 0xFFFFFFFFFFFFFFFF,
            (H[5] + f) & 0xFFFFFFFFFFFFFFFF,
            (H[6] + g) & 0xFFFFFFFFFFFFFFFF,
            (H[7] + h) & 0xFFFFFFFFFFFFFFFF
        ]

    digest = b''.join(x.to_bytes(8, 'big') for x in H)
    return digest.hex()

# Convenience wrappers
def sha512_of_string(s: str) -> str:
    return sha512(s)


def sha512_of_file(path: str) -> str:
    with open(path, 'rb') as f:
        data = f.read()
    return sha512(data)


# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute SHA-512 hash of a string or file.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--string', help='String to hash')
    group.add_argument('-f', '--file', help='File to hash')
    args = parser.parse_args()

    if args.string is not None:
        digest = sha512_of_string(args.string)
        print(f"SHA-512 ({args.string}): {digest}")
    else:
        try:
            digest = sha512_of_file(args.file)
            print(f"SHA-512 (file): {digest}")
        except FileNotFoundError:
            print(f"File not found: {args.file}", file=sys.stderr)
            sys.exit(2)