import socket

def client_program():
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Get the server's IP address (assuming it's running locally for now)
    host = socket.gethostbyname(socket.gethostname())  # or 'localhost'
    port = 5000  # The same port as the server

    # Connect to the server
    client_socket.connect((host, port))
    print(f"Connected to server at {host}:{port}")

    # Send/Receive data to/from the server
    while True:
        message = input("Enter message to send to server: ")
        if message.lower() == 'exit':
            break  # If the message is 'exit', close the connection
        client_socket.send(message.encode())  # Send the message to the server

        data = client_socket.recv(1024).decode()  # Receive the server's reply
        print(f"Received from server: {data}")

    # Close the connection when done
    client_socket.close()

if __name__ == '__main__':
    client_program()
