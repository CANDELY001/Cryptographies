# Pure Python implementation of Triple DES (3DES)
# Note: This is simplified for educational purposes

# Initial permutation table
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17,  9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final permutation table
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41,  9, 49, 17, 57, 25]

# DES functions (simplified: just permutation and XOR for demonstration)
def permute(block, table):
    return [block[i - 1] for i in table]

def xor(t1, t2):
    return [a ^ b for a, b in zip(t1, t2)]

def str_to_bitlist(data):
    result = []
    for c in data:
        bits = bin(ord(c))[2:].rjust(8, '0')
        result.extend([int(b) for b in bits])
    return result

def bitlist_to_str(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)

def des_round(block, key):
    # Very simplified "round" for demonstration
    left = block[:32]
    right = block[32:]
    # Example: XOR right with key bits and swap
    new_right = xor(left, key[:32])
    return right + new_right

def des_encrypt_block(block, key):
    block = permute(block, IP)
    for _ in range(16):
        block = des_round(block, key)
    block = permute(block, FP)
    return block

def des_decrypt_block(block, key):
    block = permute(block, IP)
    for _ in range(16):
        block = des_round(block, key)  # symmetric for this simplified example
    block = permute(block, FP)
    return block

def triple_des_encrypt(plaintext, key1, key2, key3):
    block = str_to_bitlist(plaintext)
    block = des_encrypt_block(block, str_to_bitlist(key1))
    block = des_decrypt_block(block, str_to_bitlist(key2))
    block = des_encrypt_block(block, str_to_bitlist(key3))
    return bitlist_to_str(block)

def triple_des_decrypt(ciphertext, key1, key2, key3):
    block = str_to_bitlist(ciphertext)
    block = des_decrypt_block(block, str_to_bitlist(key3))
    block = des_encrypt_block(block, str_to_bitlist(key2))
    block = des_decrypt_block(block, str_to_bitlist(key1))
    return bitlist_to_str(block)

# Example usage
plaintext = "ABCDEFGH"  # 8 characters = 64 bits
key1 = "12345678"
key2 = "abcdefgh"
key3 = "ABCDEFGH"

cipher = triple_des_encrypt(plaintext, key1, key2, key3)
print("Cipher:", cipher)

decipher = triple_des_decrypt(cipher, key1, key2, key3)
print("Decipher:", decipher)
