from Crypto.Cipher import AES
import base64

# PASTE THESE VALUES FROM YOUR SESSION:
ENCRYPTED_BASE64 = "0MFmQ12S2mAZOxgCgwp3sbsbjwl+kunjKU5azv86HG7rp8rGT"  # From Wireshark
AES_KEY_HEX = "b463413c6d3a89f17e3a9e5bcf62ae66db677e54ee154e02578c9afcec975150"  # From sender's output

def decrypt():
    try:
        # Convert the AES key from hex to bytes
        key = bytes.fromhex(AES_KEY_HEX)
        
        # Decode the Base64-encoded encrypted data
        raw_data = base64.b64decode(ENCRYPTED_BASE64 + '==')  # Adding padding if necessary
        
        # Ensure the raw_data length is sufficient for nonce, tag, and ciphertext
        if len(raw_data) < 32:
            raise ValueError("Insufficient data length after Base64 decoding.")
        
        # Extract nonce, tag, and ciphertext from the decoded data
        nonce = raw_data[:16]
        tag = raw_data[16:32]
        ciphertext = raw_data[32:]
        
        # Initialize the AES cipher in EAX mode with the given nonce
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        
        # Decrypt the ciphertext and verify its authenticity
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        # Output the decrypted plaintext
        print("✅ Decrypted:", plaintext.decode())
    except Exception as e:
        print("❌ Failed:", str(e))
        print("Debug Info:")
        print("- Key:", AES_KEY_HEX)
        print("- Encrypted Base64 Data:", ENCRYPTED_BASE64)
        print("- Data Length:", len(raw_data), "bytes" if 'raw_data' in locals() else "N/A")
        print("- Nonce:", nonce.hex() if 'nonce' in locals() else "N/A")
        print("- Tag:", tag.hex() if 'tag' in locals() else "N/A")

if __name__ == "__main__":
    decrypt()
