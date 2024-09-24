import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os

# AES key and IV generation
aes_key = os.urandom(32)  # 256-bit AES key
iv = os.urandom(16)       # 128-bit IV

def rsa_encrypt(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Encrypt and decrypt functions for AES
def encrypt_message(message, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode()) + encryptor.finalize()

def decrypt_message(ciphertext, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostbyname(socket.gethostname())
    port = 5000

    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")

    # Step 1: Receive the server's RSA public key
    public_pem = client_socket.recv(1024)
    public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
    print("Received RSA public key from server")

    # Step 2: Encrypt the AES key using the server's public key
    encrypted_aes_key = rsa_encrypt(aes_key, public_key)

    # Step 3: Send the encrypted AES key and IV to the server
    client_socket.send(encrypted_aes_key)
    client_socket.send(iv)
    print("AES key and IV sent to server")

    # Step 4: Start communication using AES
    while True:
        message = input("Enter message to send to server: ")
        if message.lower() == 'exit':
            break
        encrypted_message = encrypt_message(message, aes_key, iv)
        client_socket.send(encrypted_message)

        data = client_socket.recv(1024)
        decrypted_message = decrypt_message(data, aes_key, iv)
        print(f"Decrypted message from server: {decrypted_message.decode()}")

    client_socket.close()

if __name__ == '__main__':
    client_program()
