from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
# Chargement de la clé privée
private_key = ECC.import_key(open("user_private.pem").read())
# Le message d’authentification
message = b"AUTHENTICATE: user123"
hash_obj = SHA256.new(message)
# Création du signataire
signer = DSS.new(private_key, 'fips-186-3')
# Signature
signature = signer.sign(hash_obj)
print("Signature envoyée :", signature.hex())
# (Le client envoie message + signature + sa clé publique au serveur)