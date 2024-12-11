import socket
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crypto import aes_decrypt, keys

# Constants
SERVER_HOST = '127.0.0.1'  
SERVER_PORT = 5555       
EXPECTED_PAYLOAD = "Wireless Security-Project3-Quantum Crypto"  
TIMEOUT = 600

BUFFER_SIZE = 1024

def decode_packet(encrypted_payload, key):
    return aes_decrypt(encrypted_payload, key)

def tcp_client():
    try:
        print("[INFO] Connecting to server...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(TIMEOUT)
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print("[INFO] Connected to server.")

            total_packets = int(client_socket.recv(1024).decode('utf-8'))
            print(f"[INFO] Total packets to receive: {total_packets}")
            client_socket.sendall(b"READY")  

            packets_received = 0
            last_progress = 0

            while True:
                encrypted_packet = client_socket.recv(1024)
                if not encrypted_packet:
                    print("[ERROR] Received an empty packet.")
                    break

                if encrypted_packet == b"END":
                    print(f"[INFO] Transmission complete. Received all {total_packets} packets.")
                    break

                decrypted_message = None
                used_key = None  # Track the key used for decryption

                for key in keys.values():
                    try:
                        decrypted_message = aes_decrypt(encrypted_packet, key)
                        if decrypted_message == EXPECTED_PAYLOAD:
                            used_key = key  # Save the key used for successful decryption
                            break
                    except Exception:
                        continue

                if decrypted_message:
                    packets_received += 1
                    client_socket.sendall(f"ACK:{packets_received - 1}".encode('utf-8'))

                    # Calculate and show progress percentage
                    current_progress = (packets_received / total_packets) * 100
                    print(f"[INFO] Decrypted message: {decrypted_message}")
                    print(f"[INFO] Decryption key: {used_key.hex()}")  # Show the decryption key
                    print(f"[INFO] Progress: {current_progress:.2f}%")  # Show progress percentage

                    if current_progress >= last_progress + 10:
                        last_progress += 10
                        print(f"[INFO] Client transmission progress: {last_progress}% completed.")
                else:
                    client_socket.sendall(b"NACK")

    except Exception as e:
        print(f"[ERROR] Client encountered an error: {e}")
    finally:
        print("[INFO] Connection closed.")

if __name__ == "__main__":
    tcp_client()
