#Exercice 3: ECC (V1: utilisation de la bibliothèque pycryprodome)
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
# 1. Génération de la paire de clés ECC avec la courbe P-256
key = ECC.generate(curve='P-256')
private_key = key
public_key = key.public_key()
# 2. Affichage de la clé privée et publique
# Utilisation de 'PEM' comme format pour les clés
private_key_pem = private_key.export_key(format='PEM') # Exportation au format PEM
public_key_pem = public_key.export_key(format='PEM') # Exportation au format PEM
print("Clé privée (au format PEM) :\n", private_key_pem)
print("Clé publique (au format PEM) :\n", public_key_pem)
# 3. Signature d'un message avec la clé privée
message = b"Message important"
h = SHA256.new(message) # Hachage du message avec SHA-256
# Création de l'objet signature avec l'algorithme DSS (Digital Signature Standard)
signer = DSS.new(private_key, 'fips-186-3') ## crée un objet qui utilise DSS basé sur la norme FIPS-186-3 pour ECDSA
signature = signer.sign(h) # Signature du message haché
print("\nSignature du message :", signature.hex())
# 4. Vérification de la signature avec la clé publique
verifier = DSS.new(public_key, 'fips-186-3')
try:
    verifier.verify(h, signature) # Vérification de la signature
    print("\nLa signature est valide.")
except ValueError:
    print("\nLa signature n'est pas valide.")