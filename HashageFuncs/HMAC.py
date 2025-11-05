import argparse
import binascii
from SHA2 import sha256  
def hmac_sha256(key: bytes, message: bytes) -> bytes:
    block_size = 64  # SHA-256 block size

    # Step 1: Normalize key
    if len(key) > block_size:
        key = binascii.unhexlify(sha256(key))  # convert hex string to bytes
    if len(key) < block_size:
        key = key + b'\x00' * (block_size - len(key))

    # Step 2: Create inner and outer pads
    o_key_pad = bytes((x ^ 0x5C) for x in key)
    i_key_pad = bytes((x ^ 0x36) for x in key)

    # Step 3: Compute HMAC
    inner_hash = binascii.unhexlify(sha256(i_key_pad + message))  # bytes
    hmac_result = binascii.unhexlify(sha256(o_key_pad + inner_hash))  # bytes

    return hmac_result

# ----------------------------
# Example usage
# ----------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute HMAC-SHA256 of a string.")
    parser.add_argument('-s', '--string', help='String to hash', required=True)
    args = parser.parse_args()

    key = b"JHEZIYGRYEK008676"
    message_bytes = args.string.encode()

    digest = hmac_sha256(key, message_bytes)

    print("Message:", args.string)
    print("Key:", key.decode())
    print("HMAC-SHA256 Signature:", digest.hex())
