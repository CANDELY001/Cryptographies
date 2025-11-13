# L'utilisateur saisit le code affiché sur son appli
user_code = input("Entrez le code 2FA : ")
if totp.verify(user_code):
    print(" Authentification 2FA réussie.")
else:
    print("Code invalide ou expiré.")