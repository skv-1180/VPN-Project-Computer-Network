import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Pre-shared key and IV (same as server)
key = b'0123456789abcdef0123456789abcdef'  # 32-byte AES key
iv = b'0123456789abcdef'                   # 16-byte IV

def encrypt_message(message):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode()) + encryptor.finalize()

def decrypt_message(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def client_program():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostbyname(socket.gethostname())
    port = 5000

    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")

    while True:
        message = input("Enter message to send to server: ")
        if message.lower() == 'exit':
            break
        encrypted_message = encrypt_message(message)
        client_socket.send(encrypted_message)

        data = client_socket.recv(1024)
        decrypted_message = decrypt_message(data)
        print(f"Decrypted message from server: {decrypted_message.decode()}")

    client_socket.close()

if __name__ == '__main__':
    client_program()
