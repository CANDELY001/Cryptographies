#!/usr/bin/env python3     
import argparse               # Imports argparse to handle command-line arguments

################# Helper functions ################

def byte_to_bits(data: bytes) -> list:
    bits = []                                                     
    for b in data:                                                # Iterate through each byte in the input
        bits.extend([(b >> i) & 1 for i in reversed(range(8))])   # Convert byte to bits (MSB to LSB)
    return bits                                                   # Return bit list

def bits_to_byte(bits: list) -> int:
    byte = 0                                                      
    for bit in bits:                                              
        byte = (byte << 1) | bit                                  # Shift bits left and append current bit
    return byte                                                   # Return the constructed byte

def permute(bits, table):
    return [bits[i-1] for i in table]                             # Reorder bits according to the DES table (1-indexed)

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]                          # Bitwise XOR for two bit lists

def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)               # Calculate padding length
    if pad_len == 0:                                              # If already a multiple of block size
        pad_len = block_size                                      # Add a full block of padding
    return data + bytes([pad_len] * pad_len)                      # Append padding bytes

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]                                            # Get value of last byte (padding length)
    if data[-pad_len:] != bytes([pad_len] * pad_len):             # Validate padding format
        raise ValueError("Invalid padding")                       # Raise error if invalid padding
    return data[:-pad_len]                                        # Remove padding bytes

#################### DES Tables (simplified) ####################


IP = [ ... ]     # Initial Permutation (IP) table used in DES
IP_INV = [ ... ] # Inverse Initial Permutation (IP⁻¹) table for reversing the process


#################### DES Core Functions ########################


def f(right, subkey):
    # Simplified DES round function (for demo) — just XOR right half with subkey
    return xor(right, subkey)

def generate_subkeys(key_bits):
    # Simplified key schedule — repeats the same 48-bit key for all 16 rounds
    return [key_bits[:48]] * 16

def des_encrypt_block(block_bits, subkeys):
    block_bits = permute(block_bits, IP)                          # Apply initial permutation
    left, right = block_bits[:32], block_bits[32:]                # Split block into left and right halves
    for k in subkeys:                                             # Loop through each of the 16 rounds
        temp = right                                              # Save current right half
        right = xor(left, f(right, k))                            # Compute new right = left XOR f(right, key)
        left = temp                                               # Swap halves
    combined = right + left                                       # Final swap (right then left)
    return permute(combined, IP_INV)                              # Apply inverse permutation to get ciphertext block

def des_decrypt_block(block_bits, subkeys):
    block_bits = permute(block_bits, IP)                          # Apply initial permutation
    left, right = block_bits[:32], block_bits[32:]                # Split block
    for k in reversed(subkeys):                                   # Use subkeys in reverse order for decryption
        temp = right
        right = xor(left, f(right, k))                            # Same logic as encryption
        left = temp
    combined = right + left
    return permute(combined, IP_INV)                              # Apply inverse permutation

def bytes_to_bits_blocks(data: bytes):
    # Generator: split input bytes into 8-byte chunks and yield their bit representation
    for i in range(0, len(data), 8):
        yield byte_to_bits(data[i:i+8])

def bits_blocks_to_bytes(blocks):
    out = bytearray()                                             # Create an empty output byte array
    for bbits in blocks:                                          # For each 64-bit block
        out.extend(bytes([bits_to_byte(bbits[i:i+8])              # Convert each 8 bits back into a byte
                          for i in range(0, 64, 8)]))
    return bytes(out)                                             # Return full byte sequence

def des_encrypt_bytes(data: bytes, key_bytes: bytes) -> bytes:
    key_bits = byte_to_bits(key_bytes[:8])                        # Convert key to bits (use first 8 bytes)
    subkeys = generate_subkeys(key_bits)                          # Generate 16 round subkeys
    out_blocks = []                                               # Store encrypted blocks
    for block_bits in bytes_to_bits_blocks(data):                 # Iterate over 8-byte chunks
        ct_bits = des_encrypt_block(block_bits, subkeys)          # Encrypt each block
        out_blocks.append(ct_bits)
    return bits_blocks_to_bytes(out_blocks)                       # Combine all blocks into ciphertext bytes

def des_decrypt_bytes(data: bytes, key_bytes: bytes) -> bytes:
    key_bits = byte_to_bits(key_bytes[:8])                        # Convert key to bits
    subkeys = generate_subkeys(key_bits)                          # Generate subkeys
    out_blocks = []                                               # Store decrypted blocks
    for block_bits in bytes_to_bits_blocks(data):                 # Iterate through ciphertext blocks
        pt_bits = des_decrypt_block(block_bits, subkeys)          # Decrypt each block
        out_blocks.append(pt_bits)
    return bits_blocks_to_bytes(out_blocks)                       # Combine into plaintext bytes

# ------------------------
# CLI (Command Line Interface)
# ------------------------

def main():
    parser = argparse.ArgumentParser(description="Simple DES encrypt/decrypt")  # Create CLI parser
    parser.add_argument('-s', '--string', help='Input string', required=True)   # Input text or ciphertext
    parser.add_argument('-k', '--key', help='8-byte key', default='12345678')   # Encryption key
    parser.add_argument('--decrypt', action='store_true', help='Decrypt mode')  # Flag for decryption
    args = parser.parse_args()                                                  # Parse command-line arguments

    key_bytes = args.key.encode('utf-8')                                        # Convert key to bytes
    key_bytes = key_bytes.ljust(8, b'\x00')[:8]                                 # Pad or truncate to exactly 8 bytes

    if not args.decrypt:                                                        # If encryption mode
        plaintext = args.string.encode('utf-8')                                 # Convert plaintext to bytes
        padded = pkcs7_pad(plaintext, 8)                                        # Apply PKCS#7 padding
        ciphertext = des_encrypt_bytes(padded, key_bytes)                       # Encrypt data
        print("Plaintext:", plaintext)
        print("Key:", key_bytes)
        print("Ciphertext (hex):", ciphertext.hex())                            # Output ciphertext as hex string
    else:                                                                       # If decryption mode
        try:
            ct = bytes.fromhex(args.string)                                     # Convert hex string to bytes
        except ValueError:
            print("Decrypt input must be hex string")                           # Handle invalid hex input
            return
        decrypted_padded = des_decrypt_bytes(ct, key_bytes)                     # Decrypt ciphertext
        try:
            plaintext = pkcs7_unpad(decrypted_padded)                           # Try to remove padding
        except ValueError:
            plaintext = decrypted_padded                                        # Keep raw data if padding invalid
        print("Decrypted (raw):", plaintext)                                    # Show raw bytes
        print("Decrypted (utf-8):", plaintext.decode('utf-8', errors='replace'))# Decode to readable text

if __name__ == "__main__":                                                     # Only run main if script executed directly
    main()
