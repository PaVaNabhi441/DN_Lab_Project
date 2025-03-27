# --------------------------
# RECEIVER.py (TCP Server)
# --------------------------
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import socket
import base64

def generate_dh_key():
    key = ECC.generate(curve='secp256r1')
    # Save private key for later decryption
    with open('receiver_private.pem', 'wb') as f:
        f.write(key.export_key(format='PEM').encode('utf-8'))
    return key

def start_receiver():
    dh_key = generate_dh_key()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 55555))
        s.listen()
        print("🔐 Waiting for connection...")
        
        conn, addr = s.accept()
        print(f"✅ Connected to {addr}")
        
        # Key exchange
        conn.send(dh_key.public_key().export_key(format='DER'))
        client_pub = ECC.import_key(conn.recv(1024), curve_name='secp256r1')
        
        # Key derivation
        shared_secret = dh_key.d * client_pub.pointQ
        shared_secret_bytes = int(shared_secret.x).to_bytes(32, 'big')
        aes_key = HKDF(shared_secret_bytes, 32, b'', SHA256)
        
        # Save session key for decryption
        with open('session_aes.key', 'wb') as f:
            f.write(aes_key)
        print(f"🔑 Saved AES Key: {aes_key.hex()}")
        
        # Message handling
        while True:
            raw_len = conn.recv(4)
            if not raw_len: break
            msg_len = int.from_bytes(raw_len, 'big')
            
            encrypted_b64 = b''
            while len(encrypted_b64) < msg_len:
                encrypted_b64 += conn.recv(msg_len - len(encrypted_b64))
            
            decrypted = decrypt_packet(encrypted_b64.decode(), aes_key)
            print(f"{decrypted}")

def decrypt_packet(encrypted_b64, key):
    raw_data = base64.b64decode(encrypted_b64)
    nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

if __name__ == "__main__":
    start_receiver()