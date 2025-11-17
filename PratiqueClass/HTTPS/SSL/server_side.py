import socket
import ssl

CERT_FILE = "server.crt"
KEY_FILE = "server.key"

# Créer un contexte SSL pour le serveur
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

# Créer un socket TCP normal
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 8443))
server_socket.listen(5)
print("Serveur en attente de connexions sécurisées...")

# Envelopper le socket d'écoute dans SSL
with context.wrap_socket(server_socket, server_side=True) as secure_socket:
    while True:
        conn, addr = secure_socket.accept()
        print(f"Connexion sécurisée établie avec {addr}")

        # Recevoir un message
        message = conn.recv(1024).decode()
        print("Message reçu :", message)

        # Envoyer une réponse
        response = "Message bien reçu. Connexion sécurisée !"
        conn.send(response.encode())

        # Fermer la connexion
        conn.close()
