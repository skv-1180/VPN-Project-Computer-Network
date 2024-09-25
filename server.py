import socket
import threading
import uuid  # Used for generating unique session IDs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import struct
import time  # For session timeout

# Session timeout in seconds (e.g., 300 seconds = 5 minutes)
SESSION_TIMEOUT = 30

# Generate RSA key pair (public and private keys)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

sessions = {}  # Dictionary to hold session data {session_id: [timestamp, client_socket, address]}

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

# Encapsulation: Create custom packet format
def encapsulate_message(encrypted_message):
    protocol = 1  # Custom protocol identifier
    payload_length = len(encrypted_message)
    
    # Pack the data into binary format (protocol: 1 byte, length: 4 bytes, payload: variable length)
    packet = struct.pack('!B I', protocol, payload_length) + encrypted_message
    return packet

def handle_client(conn, address):
    session_id = str(uuid.uuid4())  # Generate unique session ID
    sessions[session_id] = [time.time(), conn, address]  # Store session start time
    print(f"New session created with ID: {session_id} for {address}")

    # Step 1: Send the RSA public key to the client
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(public_pem)
    print(f"RSA public key sent to {address}")

    # Step 2: Receive the encrypted AES key and IV from the client
    encrypted_aes_key = conn.recv(256)  # Receiving encrypted AES key
    aes_key = rsa_decrypt(encrypted_aes_key)
    iv = conn.recv(16)  # Receiving IV (sent in plaintext for simplicity)
    print(f"AES key and IV received from {address}")

    # Start communication using AES with session management
    while True:
        try:
            packet = conn.recv(1024)
            if not packet:
                print(f"Connection closed by {address}")
                break

            # Update session timestamp
            sessions[session_id][0] = time.time()

            # Decapsulate and decrypt the received message
            encrypted_message = decapsulate_message(packet)
            decrypted_message = decrypt_message(encrypted_message, aes_key, iv)
            print(f"Decrypted message from {address}: {decrypted_message.decode()}")

            # Send reply to the client
            message = input(f"Enter reply to {address}: ")
            encrypted_message_response = encrypt_message(message, aes_key, iv)
            encapsulated_response = encapsulate_message(encrypted_message_response)
            conn.send(encapsulated_response)
        except socket.timeout:
            print(f"Session {session_id} timed out due to inactivity.")
            break

    conn.close()
    del sessions[session_id]  # Remove session once client disconnects
    print(f"Session {session_id} closed for {address}")

def server_program():
    # Create socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostbyname(socket.gethostname())
    port = 5000
    server_socket.bind((host, port))
    server_socket.listen(5)  # Allow up to 5 clients to connect
    print(f"Server listening on {host}:{port}")

    while True:
        conn, address = server_socket.accept()
        conn.settimeout(SESSION_TIMEOUT)  # Set timeout for client sessions
        client_thread = threading.Thread(target=handle_client, args=(conn, address))
        client_thread.start()  # Start a new thread for each client

if __name__ == '__main__':
    server_program()
