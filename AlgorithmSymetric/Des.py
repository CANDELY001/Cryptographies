#!/usr/bin/env python3
import argparse

# ------------------------
# Helper functions
# ------------------------

def byte_to_bits(data: bytes) -> list:
    bits = []
    for b in data:
        bits.extend([(b >> i) & 1 for i in reversed(range(8))])
    return bits

def bits_to_byte(bits: list) -> int:
    byte = 0
    for bit in bits:
        byte = (byte << 1) | bit
    return byte

def permute(bits, table):
    return [bits[i-1] for i in table]  # DES tables are 1-indexed

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# ------------------------
# DES Tables (simplified)
# ------------------------
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# ------------------------
# DES Core Functions
# ------------------------

def f(right, subkey):
    # simplified function: just xor with subkey (demo purposes)
    return xor(right, subkey)

def generate_subkeys(key_bits):
    # simplified: just repeat the key bits for 16 rounds
    return [key_bits[:48]] * 16

def des_encrypt_block(block_bits, subkeys):
    block_bits = permute(block_bits, IP)
    left, right = block_bits[:32], block_bits[32:]
    for k in subkeys:
        temp = right
        right = xor(left, f(right, k))
        left = temp
    combined = right + left  # note the swap at the end
    return permute(combined, IP_INV)

def des_decrypt_block(block_bits, subkeys):
    block_bits = permute(block_bits, IP)
    left, right = block_bits[:32], block_bits[32:]
    for k in reversed(subkeys):
        temp = right
        right = xor(left, f(right, k))
        left = temp
    combined = right + left
    return permute(combined, IP_INV)

def bytes_to_bits_blocks(data: bytes):
    for i in range(0, len(data), 8):
        yield byte_to_bits(data[i:i+8])

def bits_blocks_to_bytes(blocks):
    out = bytearray()
    for bbits in blocks:
        out.extend(bytes([bits_to_byte(bbits[i:i+8]) for i in range(0, 64, 8)]))
    return bytes(out)

def des_encrypt_bytes(data: bytes, key_bytes: bytes) -> bytes:
    key_bits = byte_to_bits(key_bytes[:8])
    subkeys = generate_subkeys(key_bits)
    out_blocks = []
    for block_bits in bytes_to_bits_blocks(data):
        ct_bits = des_encrypt_block(block_bits, subkeys)
        out_blocks.append(ct_bits)
    return bits_blocks_to_bytes(out_blocks)

def des_decrypt_bytes(data: bytes, key_bytes: bytes) -> bytes:
    key_bits = byte_to_bits(key_bytes[:8])
    subkeys = generate_subkeys(key_bits)
    out_blocks = []
    for block_bits in bytes_to_bits_blocks(data):
        pt_bits = des_decrypt_block(block_bits, subkeys)
        out_blocks.append(pt_bits)
    return bits_blocks_to_bytes(out_blocks)

# ------------------------
# CLI
# ------------------------

def main():
    parser = argparse.ArgumentParser(description="Simple DES encrypt/decrypt")
    parser.add_argument('-s', '--string', help='Input string', required=True)
    parser.add_argument('-k', '--key', help='8-byte key', default='ABCDEFGH')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt mode')
    args = parser.parse_args()

    key_bytes = args.key.encode('utf-8')
    key_bytes = key_bytes.ljust(8, b'\x00')[:8]

    if not args.decrypt:
        plaintext = args.string.encode('utf-8')
        padded = pkcs7_pad(plaintext, 8)
        ciphertext = des_encrypt_bytes(padded, key_bytes)
        print("Plaintext:", plaintext)
        print("Key:", key_bytes)
        print("Ciphertext (hex):", ciphertext.hex())
    else:
        try:
            ct = bytes.fromhex(args.string)
        except ValueError:
            print("Decrypt input must be hex string")
            return
        decrypted_padded = des_decrypt_bytes(ct, key_bytes)
        try:
            plaintext = pkcs7_unpad(decrypted_padded)
        except ValueError:
            plaintext = decrypted_padded
        print("Decrypted (raw):", plaintext)
        print("Decrypted (utf-8):", plaintext.decode('utf-8', errors='replace'))

if __name__ == "__main__":
    main()
