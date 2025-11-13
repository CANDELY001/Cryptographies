from Crypto.PublicKey import ECC
# L'utilisateur génère sa paire de clés ECC
private_key = ECC.generate(curve='P-256')
public_key = private_key.public_key()
# Sauvegarde dans des fichiers PEM
with open("user_private.pem", "wt") as f:
    f.write(private_key.export_key(format='PEM'))
with open("user_public.pem", "wt") as f:
    f.write(public_key.export_key(format='PEM'))
    print(" Clés générées et sauvegardées (user_private.pem / user_public.pem)")