import socket
from concurrent.futures import ThreadPoolExecutor

# Constants
HOST = '0.0.0.0'
PORT = 5555
TIMEOUT = 600
MAX_THREADS = 10

# Placeholder for encryption keys and AES encryption function
keys = {0: "key0", 1: "key1", 2: "key2", 3: "key3"}

def aes_encrypt(message, key):
    # Placeholder for actual AES encryption logic
    return message.encode()

# Function to handle client connection
def handle_client(conn, addr):
    conn.settimeout(TIMEOUT)
    print("[INFO] Connection from {}:{} established.".format(addr[0], addr[1]))
    try:
        # Load message from risk.bmp file and decompose into crumbs (simulated packets)
        with open("risk.bmp", "rb") as dat_file:
            dat_file.seek(0, 2)
            file_size = dat_file.tell()
            dat_file.seek(0)
            crumbs = []
            for _ in range(file_size):
                byte = int.from_bytes(dat_file.read(1), 'big')
                crumbs.append(byte % 4)  # Decompose into 4 types of crumbs
        
        total_packets = len(crumbs)
        print("[INFO] Total packets to send: {}".format(total_packets))

        # Start sending packets to the client
        for i, crumb in enumerate(crumbs):
            key = keys[crumb]
            encrypted_packet = aes_encrypt("The quick brown fox jumps over the lazy dog.", key)
            conn.sendall(encrypted_packet)

            # Print progress at 25%, 50%, 75%, and 100%
            if (i + 1) % (total_packets // 4) == 0:
                progress = ((i + 1) / total_packets) * 100
                print(f"[INFO] Progress: {progress:.0f}% completed ({i + 1}/{total_packets} packets)")

        # Send end of transmission message
        conn.sendall(b'END')
        print(f"[INFO] Transmission complete to {addr[0]}")
    except Exception as e:
        print(f"[ERROR] An error occurred: {e}")
    finally:
        # Close connection
        try:
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
        except Exception as e:
            print(f"[ERROR] Error closing connection from {addr}: {e}")
        print("[INFO] Connection from {}:{} closed.".format(addr[0], addr[1]))

# Main server function
def start_server():
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen()
            print("[INFO] Server started")
            print("[INFO] Listening on 0.0.0.0:5555")
            print("[INFO] Waiting for connections...")

            while True:
                conn, addr = server_socket.accept()
                executor.submit(handle_client, conn, addr)

if __name__ == "__main__":
    start_server()
