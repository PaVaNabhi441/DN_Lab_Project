# --------------------------
# RECEIVER.py (TCP Server)
# --------------------------
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
import socket
import base64

def generate_dh_key():
    key = ECC.generate(curve='secp256r1')
    return key

def derive_key(shared_secret):
    return HKDF(shared_secret, 32, b'', SHA256)

def start_receiver():
    # Generate DH key pair
    dh_key = generate_dh_key()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 55555))
        s.listen()
        print("🔐 Waiting for connection...")
        
        conn, addr = s.accept()
        print(f"✅ Connected to {addr}")
        
        # Send our public key
        conn.send(dh_key.public_key().export_key(format='DER'))
        
        # Receive client's public key
        client_pub = ECC.import_key(conn.recv(1024), curve_name='secp256r1')
        
        # Compute shared secret
        shared_secret = dh_key.d * client_pub.pointQ 
        aes_key = HKDF(shared_secret.to_bytes(), 32, b'', SHA256)
        
        print(f"🔑 Derived AES Key: {aes_key.hex()}")
        
        while True:
            # Read message length
            raw_len = conn.recv(4)
            if not raw_len: break
            msg_len = int.from_bytes(raw_len, 'big')
            
            # Read full message
            encrypted_b64 = b''
            while len(encrypted_b64) < msg_len:
                encrypted_b64 += conn.recv(msg_len - len(encrypted_b64))
            
            decrypted = decrypt_packet(encrypted_b64.decode(), aes_key)
            print(f"🔓 Decrypted: {decrypted}")

def decrypt_packet(encrypted_b64, key):
    raw_data = base64.b64decode(encrypted_b64)
    nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

if __name__ == "__main__":
    start_receiver()