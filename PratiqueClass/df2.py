#Exercice 2: DH (utilisation de cryptography)
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
# Étape 1 : Génération des paramètres de Diffie-Hellman g=2, taille de la clé (2048 bits).
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
print(f"Paramètres publics :\np = {parameters.parameter_numbers().p}\ng = {parameters.parameter_numbers().g}")
# Étape 2 : Génération des clés privées pour Alice et Bob Les clés privées sont des nombres aléatoires choisis dans l'intervalle [1,P-1]
private_key_alice = parameters.generate_private_key()
private_key_bob = parameters.generate_private_key()
print(f"Clé privée d'Alice : {private_key_alice.private_numbers().x}")
print(f"Clé privée de Bob : {private_key_bob.private_numbers().x}")
# Étape 3 : Clés publiques
public_key_alice = private_key_alice.public_key() #public_key_alice=g^(private_key_alice) mod p
public_key_bob = private_key_bob.public_key() #public_key_bob=g^(private_key_bob) mod p
# Affichage des clés publiques
public_key_alice_bytes = public_key_alice.public_numbers().y # Extrait la partie publique sous forme d'un entier pour un affichage
public_key_bob_bytes = public_key_bob.public_numbers().y
print("Clé publique d'Alice :", public_key_alice_bytes)
print("Clé publique de Bob :", public_key_bob_bytes)
# Étape 4 : Calcul des clés partagées
#Alice et Bob utilisent leurs clés privées respectives et les clés publiques de l'autre pour calculer une clé partagée.
shared_key_alice = private_key_alice.exchange(public_key_bob)
shared_key_bob = private_key_bob.exchange(public_key_alice)
# Vérification
print("\nClé partagée d'Alice :", shared_key_alice.hex())
print("Clé partagée de Bob :", shared_key_bob.hex())
print("Échange réussi :", shared_key_alice == shared_key_bob)