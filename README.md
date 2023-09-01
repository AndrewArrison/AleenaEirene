# AleenaEirene

This Python script provides a simple command-line interface for encrypting and decrypting files using password-based key derivation and the Fernet symmetric encryption scheme.

## Features

- Securely encrypt files with a user-provided password.
- Decrypt encrypted files with the same password.
- Strong security with PBKDF2 for key derivation and Fernet for encryption.
- Secure deletion of original and encrypted files after successful operations.

## Getting Started

1. **Prerequisites**: Ensure you have Python 3.x installed on your system.

2. **Installation**: Clone or download this repository to your local machine.

3. **Setup**: Install the required Python packages by running the following command:

   ```shell
   pip install cryptography


# Usage Instructions

## Encryption:

Enter the path of the file you want to encrypt.
Provide a strong password when prompted.
The script will securely encrypt the file and delete the original.

## Decryption:

Enter the path of the encrypted file (without the ".aleena" extension).
Provide the same password used for encryption.
The script will decrypt the file and delete the encrypted version.

## Security Considerations
Keep your password secure, as it's essential for both encryption and decryption.
The script uses PBKDF2 for key derivation and Fernet for encryption, which are considered secure cryptographic methods.
The original and encrypted files are securely deleted to prevent data leakage.
