import socket
import ssl

# Créer un contexte SSL et charger le certificat auto-signé
context = ssl.create_default_context()
context.check_hostname = True
context.load_verify_locations(cafile="server.crt")

# Créer un socket et l'envelopper avec SSL
with socket.create_connection(("localhost", 8443)) as client_socket:
    with context.wrap_socket(client_socket, server_hostname="localhost") as secure_socket:
        print("Connexion sécurisée au serveur établie.")

        # Envoyer un message
        message = "Bonjour, serveur sécurisé !"
        secure_socket.send(message.encode())
        print("Message envoyé :", message)

        # Recevoir une réponse (doit être ici!)
        response = secure_socket.recv(1024).decode()
        print("Réponse du serveur :", response)
