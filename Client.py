import socket
from Crypto import *
import random

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555

# Function to connect to the server and receive packets
def tcp_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[INFO] Connected to {SERVER_HOST}:{SERVER_PORT}")

            total_packets = 0
            successfully_decrypted = 0
            failed_attempts = {}  # Track failed decryption attempts by packet number
            received_packets = []  # Track packets received to reconstruct the original message

            # Continuously receive encrypted packets
            while True:
                encrypted_packet = client_socket.recv(1024)
                if not encrypted_packet:
                    break

                # Check for end signal
                if encrypted_packet == b'END':
                    print(f"[INFO] Received end of transmission signal. Closing connection.")
                    break

                # Track total packets received
                packet_number = total_packets
                total_packets += 1

                # Randomly select a key to attempt decryption
                key_attempts = list(keys.values())
                key_attempts_failed = failed_attempts.get(packet_number, [])

                for key in key_attempts:
                    if key in key_attempts_failed:
                        continue  # Skip keys that have failed already for this packet

                    try:
                        decrypted_message = aes_decrypt(encrypted_packet, key)
                        if "The quick brown fox jumps over the lazy dog." in decrypted_message:
                            print(f"[INFO] Successfully decrypted: {decrypted_message}")
                            client_socket.sendall(b'ACK')
                            successfully_decrypted += 1
                            received_packets.append(decrypted_message)  # Add the decrypted message
                            break
                        else:
                            print(f"[WARN] Incorrect decryption result.")
                            client_socket.sendall(b'NACK')
                    except Exception:
                        print(f"[WARN] Decryption failed with the selected key.")
                        key_attempts_failed.append(key)
                        client_socket.sendall(b'NACK')

                failed_attempts[packet_number] = key_attempts_failed

                # Update progress
                if total_packets > 0:
                    progress = (successfully_decrypted / total_packets) * 100
                    print(f"[INFO] Decryption Progress: {progress:.2f}%")

                # Stop once all packets are successfully decrypted
                if successfully_decrypted == len(failed_attempts):
                    print(f"[INFO] All packets successfully decrypted. Closing connection.")
                    break

            # Print the reconstructed message from all successfully decrypted packets
            reconstructed_message = "".join(received_packets)
            print(f"[INFO] Reconstructed message: {reconstructed_message}")

        except Exception as e:
            print(f"[ERROR] An error occurred: {e}")
        finally:
            print(f"[INFO] Connection closed.")

if __name__ == "__main__":
    tcp_client()
