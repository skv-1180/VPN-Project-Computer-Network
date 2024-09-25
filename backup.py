from pyroute2 import IPRoute

def create_tun_interface(name='tun0', ip_address='10.0.0.1'):
    ip = IPRoute()
    
    # Create a TUN interface
    ip.link('add', ifname=name, kind='tun')
    # Bring the interface up
    ip.link('set', index=ip.link_lookup(ifname=name)[0], state='up')
    print(f"{name} interface created and brought up.")
    
    # Set an IP address for the TUN interface
    ip.addr('add', index=ip.link_lookup(ifname=name)[0], address=ip_address, prefixlen=24)
    print(f"IP address {ip_address} set for {name}")

def add_route(vpn_ip, tun_interface):
    ip = IPRoute()
    # Add a route for the VPN IP
    ip.route('add', dst=vpn_ip, oif=ip.link_lookup(ifname=tun_interface)[0])
    print(f"Route added for {vpn_ip} through {tun_interface}")

if __name__ == "__main__":
    create_tun_interface()
    add_route('0.0.0.0/0', 'tun0')  # Route all traffic through the VPN



# ---------
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import struct
from tun_setup import create_tun_interface, add_route

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# RSA decryption function
def rsa_decrypt(encrypted_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# AES encryption and decryption
def encrypt_message(message, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode()) + encryptor.finalize()

def decrypt_message(ciphertext, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Main server program
def server_program():
    create_tun_interface()  # Create the TUN interface
    add_route('0.0.0.0/0', 'tun0')  # Route traffic through the TUN interface
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostbyname(socket.gethostname())
    port = 5000
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    conn, address = server_socket.accept()
    print(f"Connection from {address}")

    # Send RSA public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(public_pem)
    print("RSA public key sent to client")

    # Receive encrypted AES key and IV
    encrypted_aes_key = conn.recv(256)
    aes_key = rsa_decrypt(encrypted_aes_key)
    iv = conn.recv(16)
    print("AES key and IV received and decrypted")

    while True:
        packet = conn.recv(1024)
        if not packet:
            break

        # Handle packet processing here...
        # Example: Decrypt message, send a response, etc.

    conn.close()

if __name__ == '__main__':
    server_program()
#-------------
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import struct
from tun_setup import create_tun_interface, add_route

def client_program():
    create_tun_interface()  # Create the TUN interface
    add_route('10.0.0.1/24', 'tun0')  # Route traffic to the VPN server

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = input("Enter server IP: ")  # Get server IP from user
    port = 5000
    client_socket.connect((server_ip, port))
    print(f"Connected to server at {server_ip}:{port}")

    # Handle key exchange and communication
    # Send encrypted messages...

if __name__ == '__main__':
    client_program()
