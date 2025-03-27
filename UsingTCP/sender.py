# --------------------------
# SENDER.py (TCP Client)
# --------------------------
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import socket
import base64

def generate_dh_key():
    return ECC.generate(curve='secp256r1')

def connect_to_receiver():
    dh_key = generate_dh_key()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', 55555))  # ← REPLACE WITH RECEIVER'S IP
        
        # Exchange DH keys
        s.send(dh_key.public_key().export_key(format='DER'))
        server_pub = ECC.import_key(s.recv(1024), curve_name='secp256r1')
        
        # Compute shared secret (x-coordinate only)
        shared_secret = dh_key.d * server_pub.pointQ
        shared_secret_bytes = int(shared_secret.x).to_bytes(32, 'big')
        aes_key = HKDF(shared_secret_bytes, 32, b'', SHA256)
        
        print(f"🔑 Derived AES Key: {aes_key.hex()}")
        
        while True:
            message = input("Enter message: ")
            encrypted = encrypt_message(message, aes_key)
            s.send(len(encrypted).to_bytes(4, 'big'))
            s.send(encrypted.encode())

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

if __name__ == "__main__":
    connect_to_receiver()