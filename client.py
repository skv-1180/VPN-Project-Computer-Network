import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import struct  # Used for packing/unpacking the custom packet

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

# Encapsulation: Create custom packet format
def encapsulate_message(encrypted_message):
    protocol = 1  # Custom protocol identifier
    payload_length = len(encrypted_message)
    
    # Pack the data into binary format (protocol: 1 byte, length: 4 bytes, payload: variable length)
    packet = struct.pack('!B I', protocol, payload_length) + encrypted_message
    return packet

# Decapsulate the received message
def decapsulate_message(packet):
    protocol, payload_length = struct.unpack('!B I', packet[:5])  # Extract protocol and payload length
    encrypted_message = packet[5:5 + payload_length]  # Extract the actual payload (encrypted message)
    return encrypted_message

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

    # Step 4: Start communication using AES with encapsulation
    while True:
        message = input("Enter message to send to server (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break

        # Encrypt and encapsulate the message
        encrypted_message = encrypt_message(message, aes_key, iv)
        encapsulated_message = encapsulate_message(encrypted_message)
        client_socket.send(encapsulated_message)

        # Receive and decapsulate the response
        packet = client_socket.recv(1024)
        encrypted_message_from_server = decapsulate_message(packet)
        decrypted_message = decrypt_message(encrypted_message_from_server, aes_key, iv)
        
        try:
            print(f"Decrypted message from server: {decrypted_message.decode()}")
        except UnicodeDecodeError as e:
            print(f"Decryption error: {e}")
            print(f"Raw decrypted message: {decrypted_message}")

    client_socket.close()

if __name__ == '__main__':
    client_program()
