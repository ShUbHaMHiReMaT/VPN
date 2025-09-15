# client.py
import socket
import oqs # CHANGED: Import liboqs
import threading
from tunnel import forward_traffic

def handle_local_connection(local_conn, server_socket, shared_secret):
    """Handles traffic from a local application and forwards it to the VPN server."""
    try:
        forward_thread1 = threading.Thread(target=forward_traffic, args=(local_conn, server_socket, shared_secret))
        forward_thread2 = threading.Thread(target=forward_traffic, args=(server_socket, local_conn, shared_secret))

        forward_thread1.start()
        forward_thread2.start()
        forward_thread1.join()
        forward_thread2.join()
    except Exception as e:
        print(f"[Client] Error handling local connection: {e}")
    finally:
        local_conn.close()


def main():
    """Main function to start the client and listen for local connections."""
    server_host = "127.0.0.1"
    server_port = 1337
    local_host = "127.0.0.1"
    local_port = 8080

    kem_name = "Kyber768"

    # Listen for local application connections first
    local_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    local_listener.bind((local_host, local_port))
    local_listener.listen(5)
    print(f"[Client] Listening for local connections on {local_host}:{local_port}")

    try:
        while True:
            local_conn, addr = local_listener.accept()
            print(f"[Client] Accepted local connection from {addr}")

            # Create a new server connection for each local connection
            server_socket_thread = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket_thread.connect((server_host, server_port))
            print(f"[Client] Connected to VPN server at {server_host}:{server_port}")

            # Perform key exchange for the new connection
            # CHANGED: New syntax for KEM
            with liboqs.KeyEncapsulation(kem_name) as client_kem:
                public_key_server = server_socket_thread.recv(client_kem.details['length_public_key'])
                ciphertext, shared_secret_client = client_kem.encap_secret(public_key_server)
                server_socket_thread.sendall(ciphertext)
                print("[Client] Shared secret established.")

            handler = threading.Thread(target=handle_local_connection, args=(local_conn, server_socket_thread, shared_secret_client))
            handler.start()
    except KeyboardInterrupt:
        print("[Client] Shutting down.")
    finally:
        local_listener.close()

if __name__ == "__main__":
    main()