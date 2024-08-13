from cryptography.fernet import Fernet
import importlib.util
import sys


def load_key():
    """Load the encryption key."""
    return open('secret.key', 'rb').read()


def decrypt_file_to_memory(encrypted_file_name, key):
    """Decrypt the encrypted file and return the data in memory."""
    fernet = Fernet(key)
    with open(encrypted_file_name, 'rb') as file:
        encrypted_data = file.read()
    return fernet.decrypt(encrypted_data)


def load_config():
    """Load and decrypt the configuration file, then import it as a module."""
    key = load_key()
    decrypted_data = decrypt_file_to_memory('config.py.encrypted', key)

    # Create a temporary module from the decrypted data
    spec = importlib.util.spec_from_loader("config", loader=None)
    config_module = importlib.util.module_from_spec(spec)
    exec(decrypted_data.decode('utf-8'), config_module.__dict__)

    # Register the module in sys.modules
    sys.modules["config"] = config_module
    return config_module


# Load the configuration
config = load_config()
