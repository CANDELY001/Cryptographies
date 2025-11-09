#=============================AES===================================
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# Données initiales
plaintext = "AES encryption!" # Texte clair
key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c") # Clé en hexadécimal
# Étape 1 : Préparer les données pour le chiffrement
plaintext_bytes = plaintext.encode('utf-8') # Convertir le texte clair en bytes
plaintext_padded = pad(plaintext_bytes, AES.block_size) # Ajouter le padding pour atteindre 16 octets
# Étape 2 : Chiffrement AES
cipher = AES.new(key, AES.MODE_ECB) # Initialiser AES en mode ECB
ciphertext = cipher.encrypt(plaintext_padded) # Chiffrer les données
# Étape 3 : Déchiffrement AES
decipher = AES.new(key, AES.MODE_ECB) # Réinitialiser AES en mode ECB pour le déchiffrement
decrypted_padded = decipher.decrypt(ciphertext) # Déchiffrer les données
decrypted_plaintext = unpad(decrypted_padded, AES.block_size) # Supprimer le padding pour retrouver le texte clair
# Affichage des résultats
print("Texte clair initial :", plaintext)
print("Clé (hex) :", key.hex())
print("Texte chiffré (hex) :", ciphertext.hex())
print("Texte déchiffré :", decrypted_plaintext.decode('utf-8'))