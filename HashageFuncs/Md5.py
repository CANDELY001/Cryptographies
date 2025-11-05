import struct
import math
import argparse
import sys
import random

# Left rotation function
def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

# MD5 implementation
def md5(message):
    # Accept both str and bytes/bytearray
    if isinstance(message, (bytes, bytearray)):
        msg = bytearray(message)
    else:
        msg = bytearray(message, 'utf-8')

    # Initialize variables:
    # A = 0x67452391
    # B = 0xefcdab89
    # C = 0x98badcfe
    # D = 0x10325476

    #Randomize variables since we dont know the initial values it seems impossible to get correct déhash
    A = random.getrandbits(32)
    B = random.getrandbits(32)
    C = random.getrandbits(32)
    D = random.getrandbits(32)

    # Pre-processing: padding
    orig_len_in_bits = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0)

    # Append original length as 64-bit little-endian integer
    msg += struct.pack('<Q', orig_len_in_bits)

    # Constants for each operation
    K = [int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF for i in range(64)]

    # Rotation amounts
    s = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + \
        [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4

    # Process the message in successive 512-bit chunks
    for chunk_offset in range(0, len(msg), 64):
        chunk = msg[chunk_offset:chunk_offset + 64]
        M = list(struct.unpack('<16I', chunk))

        a, b, c, d = A, B, C, D

        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16

            # Ensure f is treated as 32-bit unsigned before rotations
            f = (f + a + K[i] + M[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + left_rotate(f, s[i])) & 0xFFFFFFFF

        # Add this chunk's hash to result so far
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    # Produce final digest as little-endian hex
    digest = struct.pack('<4I', A, B, C, D)
    return ''.join(f'{byte:02x}' for byte in digest)


# Convenience wrappers
def md5_of_string(s: str) -> str:
    return md5(s)


def md5_of_file(path: str) -> str:
    with open(path, 'rb') as f:
        data = f.read()
    return md5(data)


# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute MD5 hash of a string or file.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--string', help='String to hash')
    group.add_argument('-f', '--file', help='File to hash')
    args = parser.parse_args()

    if args.string is not None:
        digest = md5_of_string(args.string)
        print(f"MD5 (string): {digest}")
    else:
        try:
            digest = md5_of_file(args.file)
            print(f"MD5 (file): {digest}")
        except FileNotFoundError:
            print(f"File not found: {args.file}", file=sys.stderr)
            sys.exit(2)
