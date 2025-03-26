from Crypto.Cipher import AES
import socket
import base64

# Load the same key used by sender
with open('secret.key', 'rb') as f:
    KEY = f.read()

print(f"🔑 Decryption Key: {KEY.hex()}")  # Debug output

def decrypt_packet(encrypted_b64: str) -> str:
    try:
        # Decode Base64 first
        raw_data = base64.b64decode(encrypted_b64)
        
        # Extract components
        nonce = raw_data[:16]
        tag = raw_data[16:32]
        ciphertext = raw_data[32:]
        
        # Decrypt
        cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except Exception as e:
        return f"❌ Decryption failed: {e}"

def start_receiver():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('0.0.0.0', 55555))
        print("👂 Receiver listening on port 55555...")
        
        while True:
            data, addr = s.recvfrom(4096)
            try:
                encrypted_b64 = data.decode('utf-8')
                print(f"\n📩 Received Packet (Base64): {encrypted_b64[:50]}...")
                
                decrypted = decrypt_packet(encrypted_b64)
                print(f"🔓 Decrypted Message: {decrypted}")
            except Exception as e:
                print(f"⚠️ Error processing packet: {e}")

if __name__ == "__main__":
    start_receiver()