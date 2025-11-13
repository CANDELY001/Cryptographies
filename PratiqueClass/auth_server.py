from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
# Message reçu du client
message = b"AUTHENTICATE: user123"
signature_hex = input("Entrer la signature reçue : ")
signature = bytes.fromhex(signature_hex)
# Le serveur possède déjà la clé publique du client
public_key = ECC.import_key(open("user_public.pem").read())
# Vérification de la signature
hash_obj = SHA256.new(message)
verifier = DSS.new(public_key, 'fips-186-3')
try:
    verifier.verify(hash_obj, signature)
    print(" Authentification réussie : la signature est valide.")
except ValueError:
    print(" Échec : signature invalide ou message modifié.")