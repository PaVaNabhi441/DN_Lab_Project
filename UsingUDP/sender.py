from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import base64

# Load the key (must match receiver's key)
try:
    with open('secret.key', 'rb') as f:
        key = f.read()
except FileNotFoundError:
    print("❌ Error: 'secret.key' not found. Copy it from the receiver.")
    exit()

def encrypt_message(message: str) -> str:
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def send_message():
    RECEIVER_IP = '192.168.234.96'  # CHANGE TO RECEIVER'S IP
    PORT = 55555
    while True:
        message = input("Enter message (or 'quit' to exit): ")
        if message.lower() == 'quit':
            break
        encrypted = encrypt_message(message)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(encrypted.encode('utf-8'), (RECEIVER_IP, PORT))
            print("✅ Message sent!")

if __name__ == "__main__":
    send_message()