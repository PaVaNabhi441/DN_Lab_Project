# --------------------------
# decrypt.py
# --------------------------
from Crypto.Cipher import AES
import base64

def decrypt_message(encrypted_b64, aes_key):
    try:
        raw_data = base64.b64decode(encrypted_b64)
        nonce, tag, ciphertext = raw_data[:16], raw_data[16:32], raw_data[32:]
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        return f"❌ Error: {str(e)}"

def main():
    # Load saved AES key
    with open('session_aes.key', 'rb') as f:
        aes_key = f.read()
    
    # Load captured messages (base64 format)
    with open('captured_messages.txt', 'r') as f:
        messages = [line.strip() for line in f]
    
    # Decrypt all messages
    for idx, msg in enumerate(messages):
        decrypted = decrypt_message(msg, aes_key)
        print(f"Message {idx+1}: {decrypted}")

if __name__ == "__main__":
    main()