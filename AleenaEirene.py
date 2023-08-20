import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import os
import getpass
import subprocess
import base64

# Set up logging configuration
logging.basicConfig(filename='encryption_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to derive a key from a password using PBKDF2
def derive_key(password, salt):
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=300000,
            salt=salt,
            length=32,  # 256-bit key (32 bytes)
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    except Exception as e:
        logging.error(f"Error deriving key: {e}")
        raise

def encrypt_file(file_name, key):
    try:
        script_directory = os.path.dirname(__file__)
        file_path = os.path.join(script_directory, file_name)
        
        with open(file_path, 'rb') as file:
            plaintext = file.read()

        salt = os.urandom(16)  # Generate a random salt
        key = derive_key(password, salt)

        cipher = Fernet(base64.urlsafe_b64encode(key))
        encrypted_data = cipher.encrypt(plaintext)

        encrypted_file_path = file_path + ".aleena"
        with open(encrypted_file_path, 'wb') as file:
            # Store salt and encrypted data together
            file.write(salt)
            file.write(encrypted_data)
        # Securely delete the original file
        # subprocess.run(["sdelete", "-p", "-s", file_path])
        os.remove(file_path)
        # process.wait()
        logging.info(f"File encrypted: {encrypted_file_path}")
        logging.info(f"Original file securely deleted: {file_path}")
        logging.info(f"File encrypted: {encrypted_file_path}")
    except Exception as e:
        logging.error(f"Error encrypting file: {e}")
        raise

def decrypt_file(encrypted_file_path, password):
    try:
        with open(encrypted_file_path, 'rb') as file:
            salt = file.read(16)  # Read the stored salt
            encrypted_data = file.read()

        key = derive_key(password, salt)
        cipher = Fernet(base64.urlsafe_b64encode(key))
        decrypted_data = cipher.decrypt(encrypted_data)

        decrypted_file_path = encrypted_file_path.replace(".aleena", "")
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)

        logging.info(f"File decrypted: {decrypted_file_path}")

        # If decryption was successful, delete the encrypted file
        os.remove(encrypted_file_path)
        logging.info(f"Encrypted file deleted: {encrypted_file_path}")
    except Exception as e:
        logging.error(f"Error decrypting file: {e}")
        raise

if __name__ == '__main__':
    try:
        password = getpass.getpass("Enter the password: ")
        logging.info("Password inputted")
        
        while True:
            print("1. Encrypt File")
            print("2. Decrypt File")
            print("3. Exit")
            choice = int(input("Enter your choice: "))
            
            if choice == 1:
                file_path = input("Enter the path of the file to encrypt: ")
                logging.info("Encryption program started")
                encrypt_file(file_path, password)
                print("File encrypted.")
                break
            elif choice == 2:
                encrypted_file_path = input("Enter the path of the encrypted file to decrypt: ")
                encrypted_file_path = encrypted_file_path + ".aleena"
                logging.info("Decryption program started")
                decrypt_file(encrypted_file_path, password)
                print("File decrypted and encrypted file deleted.")
                break
            elif choice == 3:
                print("Exiting...")
                break  # Exit the loop and end the program
            else:
                print("Invalid choice.")
                break
        
        logging.info("Program finished")
    except Exception as e:
        logging.error(f"Error in main program: {e}")
