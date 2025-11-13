from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
# Génération des clés
key = RSA.generate(2048) #Bit size
private_key = key.export_key()
public_key = key.publickey().export_key()
# Chiffrement et déchiffrement
message = b"Bonjour, ceci est un message confidentiel."
cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
encrypted = cipher.encrypt(message)
print("Message chiffré :", encrypted)
decipher = PKCS1_OAEP.new(RSA.import_key(private_key))
decrypted = decipher.decrypt(encrypted)
print("Message déchiffré :", decrypted.decode())