from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        original_data = file.read()
    encrypted_data = fernet.encrypt(original_data)
    return encrypted_data

def main():
    # Generate and save the key
    key = generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)

    # Encrypt the configuration file
    encrypted_data = encrypt_file('configuration.py', key)
    with open('config.py.encrypted', 'wb') as enc_file:
        enc_file.write(encrypted_data)

    print("Encryption complete! The key is stored in 'secret.key' and the encrypted config is in 'config.py.encrypted'.")

if __name__ == "__main__":
    main()
