from cryptography.fernet import Fernet
import importlib.util
import os

def load_key():
    return open('secret.key', 'rb').read()

def decrypt_file_to_memory(encrypted_file_name, key):
    fernet = Fernet(key)
    with open(encrypted_file_name, 'rb') as file:
        encrypted_data = file.read()
    return fernet.decrypt(encrypted_data)

def load_config():
    key = load_key()
    decrypted_data = decrypt_file_to_memory('config.py.encrypted', key)

    # Dynamically load the configuration from decrypted data
    config_module = importlib.util.module_from_spec(importlib.util.spec_from_loader("config", loader=None))
    exec(decrypted_data.decode('utf-8'), config_module.__dict__)

    return config_module

# Example usage: loading the configuration
config = load_config()
