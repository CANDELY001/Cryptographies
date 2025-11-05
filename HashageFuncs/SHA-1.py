import argparse
import sys

def _left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sha1(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    # Pre-processing (padding)
    orig_len_bits = (8 * len(data)) & 0xffffffffffffffff
    data += b'\x80'
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'
    data += orig_len_bits.to_bytes(8, byteorder='big')

    # Initialize h0..h4
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Process the message in successive 512-bit chunks
    for chunk_offset in range(0, len(data), 64):
        chunk = data[chunk_offset:chunk_offset+64]
        w = [int.from_bytes(chunk[i:i+4], 'big') for i in range(0, 64, 4)]
        # Extend to 80 words
        for t in range(16, 80):
            val = _left_rotate(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1)
            w.append(val & 0xFFFFFFFF)

        a, b, c, d, e = h0, h1, h2, h3, h4

        for t in range(80):
            if 0 <= t <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= t <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= t <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (_left_rotate(a, 5) + f + e + k + w[t]) & 0xFFFFFFFF
            e = d
            d = c
            c = _left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Produce final hash (hex)
    digest = b''.join(x.to_bytes(4, 'big') for x in (h0, h1, h2, h3, h4))
    return digest.hex()


# Convenience wrappers
def sha1_of_string(s: str) -> str:
    return sha1(s)


def sha1_of_file(path: str) -> str:
    with open(path, 'rb') as f:
        data = f.read()
    return sha1(data)


# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute SHA-1 hash of a string or file.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--string', help='String to hash')
    group.add_argument('-f', '--file', help='File to hash')
    args = parser.parse_args()

    if args.string is not None:
        digest = sha1_of_string(args.string)
        print(f"SHA-1 (string): {digest}")
    else:
        try:
            digest = sha1_of_file(args.file)
            print(f"SHA-1 (file): {digest}")
        except FileNotFoundError:
            print(f"File not found: {args.file}", file=sys.stderr)
            sys.exit(2)
