import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Pre-shared key and IV
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

def server_program():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostbyname(socket.gethostname())
    port = 5000
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    conn, address = server_socket.accept()
    print(f"Connection from {address}")

    while True:
        data = conn.recv(1024)
        if not data:
            break
        print(f"Encrypted message from cline: {data}")
        decrypted_message = decrypt_message(data)
        print(f"Decrypted message from client: {decrypted_message.decode()}")

        message = input("Enter reply to client: ")
        encrypted_message = encrypt_message(message)
        conn.send(encrypted_message)

    conn.close()

if __name__ == '__main__':
    server_program()
