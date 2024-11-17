# SafeFileEncryptor 🔐

**SafeFileEncryptor** is a secure and user-friendly tool for encrypting and decrypting text files using AES-256 encryption. The application ensures that your sensitive files are protected with high-standard encryption methods.

## Features 🛠️:
- **AES-256 Encryption**: Industry-standard encryption to secure your files.
- **Password-Based Encryption**: Encrypt and decrypt files using a password.
- **Easy-to-Use Interface**: Simple graphical interface for effortless file encryption/decryption.
- **Logging**: Every action is logged for transparency and security purposes.
- **Cross-Platform Support**: Works on Windows, macOS, and Linux.

## Security Highlights 🔒:
- **PBKDF2 Key Derivation**: A strong key derivation function (PBKDF2) is used to securely derive the encryption key from your password.
- **Salt and IV Usage**: A unique salt and initialization vector (IV) is generated for each file to enhance security.
- **AES-256 CBC Mode**: The application uses AES encryption with CBC mode, which is a secure mode of operation for file encryption.
- **Logging**: All actions are securely logged for audit and debugging purposes. The log file is stored in a safe location.

## Installation 🛠️:
To run the application on your local machine, follow these steps:

### 1. Clone the repository:
```bash
git clone https://github.com/BrvZoo/SafeFileEncryptor.git
```
2. Install Dependencies:
```bash
   pip install -r requirements.txt
```
3. Run the Application:
```bash
python encrypt_txt.py
```
Usage 📂:

Encrypt a File: Choose the file you want to encrypt, enter your password, and click "Encrypt".
Decrypt a File: Choose an encrypted .enc file, enter the same password used for encryption, and click "Decrypt".

Contributing 💻:

We welcome contributions to improve SafeFileEncryptor. Feel free to fork the repository and submit pull requests.

![qsd](https://github.com/user-attachments/assets/0cef12f9-4a6b-45f3-81d9-8312e94cb814)

