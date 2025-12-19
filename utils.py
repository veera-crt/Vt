from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

load_dotenv()

# Generate a key if not present (for local testing, but should be in .env)
key = os.getenv('ENCRYPTION_KEY')
if not key or key == 'ReplaceWithGeneratedKeyHere':
    key = Fernet.generate_key()
    # In a real app, you MUST save this key to .env or you lose data access on restart
    print(f"WARNING: Using a temporary encryption key. SAVE THIS TO .env: {key.decode()}")

cipher_suite = Fernet(key)

def encrypt_data(data):
    if not data: return None
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(token):
    if not token: return None
    try:
        return cipher_suite.decrypt(token.encode()).decode()
    except:
        return "[Encrypted Data]"
