# server.py
import socket
import oqs # CHANGED: Import liboqs
import threading
from tunnel import forward_traffic

def handle_client(client_socket):
    """Handles a single client connection, including key exchange and traffic forwarding."""
    try:
        # 1. Kyber Key Exchange (Server Side)
        kem_name = "Kyber768"
        # CHANGED: New syntax for creating a KEM instance
        with liboqs.KeyEncapsulation(kem_name) as server_kem:
            # Server generates its key pair
            public_key_server = server_kem.generate_keypair()

            # Server sends its public key to the client
            client_socket.sendall(public_key_server)

            # Server receives the ciphertext from the client
            ciphertext = client_socket.recv(server_kem.details['length_ciphertext'])

            # Server decapsulates the ciphertext to get the shared secret
            shared_secret_server = server_kem.decap_secret(ciphertext)
            print("[Server] Shared secret established.")

        # 2. Start the tunnel
        print("[Server] Starting TCP tunnel.")
        target_host = "example.com"
        target_port = 80

        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((target_host, target_port))

        forward_thread1 = threading.Thread(target=forward_traffic, args=(client_socket, target_socket, shared_secret_server))
        forward_thread2 = threading.Thread(target=forward_traffic, args=(target_socket, client_socket, shared_secret_server))

        forward_thread1.start()
        forward_thread2.start()

        forward_thread1.join()
        forward_thread2.join()

    except Exception as e:
        print(f"[Server] Error handling client: {e}")
    finally:
        print("[Server] Client disconnected.")
        client_socket.close()
        if 'target_socket' in locals() and target_socket:
            target_socket.close()


def main():
    """Main function to start the server."""
    server_host = "127.0.0.1"
    server_port = 1337

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((server_host, server_port))
    server_socket.listen(5)
    print(f"[Server] Listening on {server_host}:{server_port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[Server] Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    main()