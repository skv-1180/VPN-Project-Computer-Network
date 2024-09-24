import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import struct  # Used for unpacking the custom packet

# Generate RSA key pair (public and private keys)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Function to decrypt AES key with RSA private key
def rsa_decrypt(encrypted_key):
    return private_key.decrypt(
        encrypted_key,
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

# Decapsulation: Extract the original message from the custom packet
def decapsulate_message(packet):
    protocol, payload_length = struct.unpack('!B I', packet[:5])  # Extract protocol and payload length
    encrypted_message = packet[5:5 + payload_length]  # Extract the actual payload (encrypted message)
    return encrypted_message

def server_program():
    # Create socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostbyname(socket.gethostname())
    port = 5000
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    conn, address = server_socket.accept()
    print(f"Connection from {address}")

    # Step 1: Send the RSA public key to the client
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(public_pem)
    print("RSA public key sent to client")

    # Step 2: Receive the encrypted AES key and IV from the client
    encrypted_aes_key = conn.recv(256)  # Receiving encrypted AES key
    aes_key = rsa_decrypt(encrypted_aes_key)
    iv = conn.recv(16)  # Receiving IV (sent in plaintext for simplicity)
    print("AES key and IV received and decrypted")

    # Start communication using AES
    while True:
        packet = conn.recv(1024)
        if not packet:
            break

        encrypted_message = decapsulate_message(packet)
        decrypted_message = decrypt_message(encrypted_message, aes_key, iv)
        print(f"Decrypted message from client: {decrypted_message.decode()}")

        message = input("Enter reply to client: ")
        encrypted_message_response = encrypt_message(message, aes_key, iv)
        encapsulated_response = encapsulate_message(encrypted_message_response)
        conn.send(encapsulated_response)

    conn.close()

# Encapsulation: Create custom packet format
def encapsulate_message(encrypted_message):
    protocol = 1  # Custom protocol identifier
    payload_length = len(encrypted_message)
    
    # Pack the data into binary format (protocol: 1 byte, length: 4 bytes, payload: variable length)
    packet = struct.pack('!B I', protocol, payload_length) + encrypted_message
    return packet

if __name__ == '__main__':
    server_program()
