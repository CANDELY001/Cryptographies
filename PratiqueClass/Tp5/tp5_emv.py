import os
import hmac
import hashlib
import random
from datetime import datetime

# --------------------------
# CONSTANTES
# --------------------------
KEY_HEX = "00112233445566778899AABBCCDDEEFF"
KEY = bytes.fromhex(KEY_HEX)
COUNTRY_CODE = "504"
PAN_PREFIX = "499999"
ATC_FILE = "atc_counter.txt"


# --------------------------
# FONCTIONS UTILITAIRES
# --------------------------

def load_atc():
    """Lire ATC depuis fichier, sinon 0"""
    if not os.path.exists(ATC_FILE):
        return 0
    with open(ATC_FILE, "r") as f:
        return int(f.read().strip())


def save_atc(atc):
    """Sauvegarde ATC dans fichier"""
    with open(ATC_FILE, "w") as f:
        f.write(str(atc))


def increment_atc():
    """Incrémente l'ATC de manière persistante"""
    atc = load_atc()
    atc += 1
    save_atc(atc)
    return atc


def generate_pan():
    """PAN de test : 499999XXXXXX1234"""
    middle = random.randint(0, 999999)
    return PAN_PREFIX + f"{middle:06d}" + "1234"


def generate_amount():
    """Montant entre 1 et 1000 MAD, formaté sur 6 digits"""
    amount = random.randint(1, 1000)
    return f"{amount:06d}"


def generate_un():
    """Unpredictable number : 4 bytes hex"""
    return f"{random.getrandbits(32):08X}"


def generate_datetime():
    """Format YYMMDDhhmmss"""
    return datetime.now().strftime("%y%m%d%H%M%S")


# --------------------------
# MESSAGE EMV
# --------------------------

def generate_message(pan, dt, amount, un, atc):
    return f"{pan}|{dt}|{amount}|{un}|{COUNTRY_CODE}|{atc:04X}"


# --------------------------
# CRYPTO : ARQC & ARPC
# --------------------------

def generate_arqc(message, key):
    mac = hmac.new(key, message.encode(), hashlib.sha256).digest()
    return mac[:8].hex().upper()  # tronqué 8 bytes


def validate_arqc_and_generate_arpc(message, arqc, key):
    recomputed = generate_arqc(message, key)
    if recomputed == arqc:
        resp_code = "00"  # approuvé
    else:
        resp_code = "05"  # refusé

    data = bytes.fromhex(arqc + resp_code)
    mac = hmac.new(key, data, hashlib.sha256).digest()
    arpc = mac[:8].hex().upper()

    return resp_code, arpc


# --------------------------
# MENU TERMINAL
# --------------------------

def nouvelle_transaction():
    pan = generate_pan()
    dt = generate_datetime()
    amount = generate_amount()
    un = generate_un()
    atc = increment_atc()

    message = generate_message(pan, dt, amount, un, atc)
    arqc = generate_arqc(message, KEY)
    resp, arpc = validate_arqc_and_generate_arpc(message, arqc, KEY)

    print("\n=== Nouvelle Transaction ===")
    print("Message :", message)
    print("ARQC    :", arqc)
    print("Decision:",
          "APPROUVÉE" if resp == "00" else "REFUSÉE", f"({resp})")
    print("ARPC    :", arpc)
    print("===========================\n")


def afficher_atc():
    print(f"ATC actuel : {load_atc()}\n")


def menu():
    while True:
        print("=== MENU ===")
        print("1. Nouvelle transaction")
        print("2. Afficher ATC")
        print("3. Quitter")
        choix = input("Choix : ")

        if choix == "1":
            nouvelle_transaction()
        elif choix == "2":
            afficher_atc()
        elif choix == "3":
            print("Au revoir !")
            break
        else:
            print("Choix invalide.\n")


if __name__ == "__main__":
    menu()
