#Exercice 2: DH (utilisation de pycryptodome)
from Crypto.Util import number
from Crypto.Random import random
# Étape 1 : Générer les paramètres Diffie-Hellman
p = number.getPrime(1024) # Génération d'un grand nombre premier
# Générer un g aléatoire dans l'intervalle [2, p-1]
g = random.randint(2, p - 1)
print(f"Paramètres publics :\np = {p}\ng = {g}")
# Étape 2 : Générer des clés privées pour deux parties
private_key_A = random.randint(1, p - 1)
private_key_B = random.randint(1, p - 1)
# Étape 3 : Calcul des clés publiques
public_key_A = pow(g, private_key_A, p)
public_key_B = pow(g, private_key_B, p)
# Étape 4 : Échange et calcul des clés partagées
shared_secret_A = pow(public_key_B, private_key_A, p)
shared_secret_B = pow(public_key_A, private_key_B, p)
# Vérification et affichage
assert shared_secret_A == shared_secret_B, "Les clés partagées ne correspondent pas !"
print("Clé partagée commune :", shared_secret_A)