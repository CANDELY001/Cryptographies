#!/usr/bin/env python3
from copy import deepcopy

# ----------------------
# AES pedagogical (simplified) with encryption/decryption
# ----------------------

# Example S-Box (partial, identity mapping for demo)
S_BOX = [i for i in range(256)]  # Replace with real AES S-Box for production
INV_S_BOX = [i for i in range(256)]  # inverse of identity mapping is itself

R_CON = [
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
]

def sub_bytes(state):
    """SubBytes step using S-Box."""
    return [[S_BOX[b] for b in row] for row in state]

def inv_sub_bytes(state):
    """Inverse SubBytes step using INV_S_BOX."""
    return [[INV_S_BOX[b] for b in row] for row in state]

def shift_rows(state):
    """ShiftRows step."""
    new_state = deepcopy(state)
    for r in range(1,4):
        new_state[r] = state[r][r:] + state[r][:r]
    return new_state

def inv_shift_rows(state):
    """Inverse ShiftRows step."""
    new_state = deepcopy(state)
    for r in range(1,4):
        new_state[r] = state[r][-r:] + state[r][:-r]
    return new_state

def add_round_key(state, round_key):
    """XOR state with round key."""
    return [[b ^ k for b,k in zip(row, kr)] for row, kr in zip(state, round_key)]

# --- Padding PKCS7 ---
def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len]*pad_len)

def unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

# --- Conversion utilities ---
def bytes2matrix(text_bytes):
    """Convert 16-byte array to 4x4 matrix"""
    return [list(text_bytes[i:i+4]) for i in range(0,16,4)]

def matrix2bytes(matrix):
    """Convert 4x4 matrix to bytes"""
    return bytes(sum(matrix, []))

# --- AES block encryption/decryption (simplified, 1 round) ---
def aes_encrypt_block(block, key):
    state = bytes2matrix(block)
    round_key = bytes2matrix(key)
    state = add_round_key(state, round_key)
    state = sub_bytes(state)
    state = shift_rows(state)
    # MixColumns omitted for simplicity
    return matrix2bytes(state)

def aes_decrypt_block(block, key):
    state = bytes2matrix(block)
    round_key = bytes2matrix(key)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_key)
    # Inverse MixColumns omitted
    return matrix2bytes(state)

# --- Main CLI ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Pedagogical AES encrypt/decrypt (16-byte block, simplified).")
    parser.add_argument('-s', '--string', help='String to encrypt/decrypt', required=True)
    parser.add_argument('-k', '--key', help='16-byte key (string)', default="abcdefghijklmnop")
    parser.add_argument('--decrypt', action='store_true', help='Decrypt mode (default is encrypt)')
    args = parser.parse_args()

    key_bytes = args.key.encode('utf-8')
    if len(key_bytes) < 16:
        key_bytes = key_bytes.ljust(16, b'\x00')
    elif len(key_bytes) > 16:
        key_bytes = key_bytes[:16]

    if not args.decrypt:
        plaintext = args.string.encode('utf-8')
        padded = pad_pkcs7(plaintext, 16)
        ciphertext = aes_encrypt_block(padded[:16], key_bytes)
        print("Plaintext:", plaintext)
        print("Key:", key_bytes)
        print("Ciphertext (hex):", ciphertext.hex())
    else:
        try:
            ct_bytes = bytes.fromhex(args.string)
        except ValueError:
            print("For decryption, provide ciphertext as hex string (e.g. -s 8f1e...).")
            exit(1)
        decrypted_padded = aes_decrypt_block(ct_bytes[:16], key_bytes)
        decrypted = unpad_pkcs7(decrypted_padded)
        print("Decrypted (raw):", decrypted)
        print("Decrypted (utf-8):", decrypted.decode('utf-8', errors='replace'))
