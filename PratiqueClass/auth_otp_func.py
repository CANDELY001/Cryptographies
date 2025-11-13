import pyotp
# L’utilisateur partage une clé secrète avec le serveur
secret = pyotp.random_base32()
print("Clé secrète 2FA :", secret)
# Génération d’un code 2FA (comme Google Authenticator)
totp = pyotp.TOTP(secret)
otp = totp.now()
print("Code généré (sur téléphone) :", otp)