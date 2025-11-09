#=============================DES==================================
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
# Données initiales
plaintext = "Cryptography!" # Texte clair
key = bytes.fromhex("133457799BBCDFF1") # Clé de chiffrement en hexadécimal
# Étape 1 : Préparer les données pour le chiffrement
plaintext_bytes = plaintext.encode('utf-8') # Convertir le texte clair en bytes
plaintext_padded = pad(plaintext_bytes, DES.block_size) # Ajouter du padding pour atteindre un multiple de 8 octets
# Étape 2 : Chiffrement DES
cipher = DES.new(key, DES.MODE_ECB) # Initialiser DES en mode ECB
ciphertext = cipher.encrypt(plaintext_padded) # Chiffrer les données
# Étape 3 : Déchiffrement DES
decipher = DES.new(key, DES.MODE_ECB) # Initialiser le déchiffreur DES en mode ECB
decrypted_padded = decipher.decrypt(ciphertext) # Déchiffrer les données
decrypted_plaintext = unpad(decrypted_padded, DES.block_size) # Supprimer le padding pour retrouver le texte clair
# Affichage des résultats
print("Texte clair initial :", plaintext)
print("Clé (hex) :", key.hex())
print("Texte chiffré (hex) :", ciphertext.hex())
print("Texte déchiffré :", decrypted_plaintext.decode('utf-8'))