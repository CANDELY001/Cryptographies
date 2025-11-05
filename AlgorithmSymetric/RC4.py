def rc4_init(key: bytes) -> list[int]:
    """Initialise le tableau S pour RC4 avec la clé fournie."""
    S = list(range(256))
    j = 0
    key_len = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_generate_keystream(S: list[int], n: int) -> list[int]:
    """Génère un keystream de n octets à partir du tableau S."""
    i = j = 0
    keystream = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    return keystream

def rc4_crypt(key: bytes, data: bytes) -> bytes:
    """Chiffrement ou déchiffrement RC4 (XOR avec le keystream)."""
    S = rc4_init(key)
    keystream = rc4_generate_keystream(S, len(data))
    return bytes([b ^ k for b, k in zip(data, keystream)])

# ----------------------------
# Exemple d'utilisation
# ----------------------------
if __name__ == "__main__":
    key = b"ma_cle_secrete"        # clé secrète
    plaintext = b"Bonjour RC4 !"    # message à chiffrer

    # Chiffrement
    ciphertext = rc4_crypt(key, plaintext)
    print("Plaintext :", plaintext)
    print("Ciphertext (hex) :", ciphertext.hex())

    # Déchiffrement (même fonction)
    decrypted = rc4_crypt(key, ciphertext)
    print("Decrypted :", decrypted)
