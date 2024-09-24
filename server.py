import socket

def server_program():
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Get the server's IP address (can be 'localhost' or '' to bind to all interfaces)
    host = socket.gethostbyname(socket.gethostname())  # or 'localhost'
    port = 5000  # Specify a port for communication

    # Bind the socket to the host and port
    server_socket.bind((host, port))

    # Listen for incoming connections (max 1 connection for now)
    server_socket.listen(1)
    print(f"Server listening on {host}:{port}")

    # Accept a connection from a client
    conn, address = server_socket.accept()
    print(f"Connection from {address}")

    # Send/Receive data from client
    while True:
        data = conn.recv(1024).decode()  # Receive data (buffer size 1024 bytes)
        if not data:
            # If no data is received, break the loop
            break
        print(f"Received from client: {data}")
        message = input("Enter reply to client: ")
        conn.send(message.encode())  # Send response to the client

    # Close the connection when done
    conn.close()

if __name__ == '__main__':
    server_program()
