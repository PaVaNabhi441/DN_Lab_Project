from Crypto.Cipher import AES
import base64

# 1. PASTE YOUR CAPTURED DATA HERE (Base64 or Hex)
wireshark_data = input("Enter the data captured in WireShark: ")  # Base64 example
# wireshark_data = "cfdc27ce7e94da76..."  # Hex example

# 2. Load the SAME key used by sender.py
with open('secret.key', 'rb') as f:
    KEY = f.read()

def decrypt(data: str, is_hex=False):
    try:
        # Convert input to bytes
        if is_hex:
            raw = bytes.fromhex(data.replace(" ", ""))
        else:
            raw = base64.b64decode(data)
        
        # Extract components
        nonce = raw[:16]
        tag = raw[16:32]
        ciphertext = raw[32:]
        
        # Decrypt
        cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except Exception as e:
        return f"❌ Decryption failed: {e}"

# Auto-detect input type (Base64/Hex)
is_hex = all(c in "0123456789abcdefABCDEF " for c in wireshark_data)
decrypted = decrypt(wireshark_data, is_hex)

print("🔑 Key:", KEY.hex())
print("📦 Encrypted:", wireshark_data[:50] + ("..." if len(wireshark_data) > 50 else ""))
print("🔓 Decrypted:", decrypted)