import os
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging

logging.basicConfig(filename='file_encryption.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=salt, 
        iterations=100000, 
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filename, password):
    try:
        if not os.path.isfile(filename):
            messagebox.showerror("Error", "The specified file does not exist.")
            return
        
        with open(filename, 'rb') as f:
            file_data = f.read()

        if not file_data:
            messagebox.showerror("Error", "The file is empty.")
            return

        salt = os.urandom(16)
        key = derive_key(password, salt)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        pad_length = 16 - (len(file_data) % 16)
        file_data_padded = file_data + bytes([pad_length]) * pad_length

        encrypted_data = encryptor.update(file_data_padded) + encryptor.finalize()

        encrypted_filename = f"{filename}.enc"
        with open(encrypted_filename, 'wb') as f:
            f.write(salt + iv + encrypted_data)

        logging.info(f"Encrypted file: {filename}")
        messagebox.showinfo("Success", f"The file has been encrypted successfully and saved as: {encrypted_filename}")

    except Exception as e:
        logging.error(f"Error during encryption: {str(e)}")
        messagebox.showerror("Error", f"Error during encryption: {str(e)}")

def decrypt_file(filename, password):
    try:
        if not os.path.isfile(filename):
            messagebox.showerror("Error", "The specified file does not exist.")
            return
        
        with open(filename, 'rb') as f:
            encrypted_data = f.read()

        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_content = encrypted_data[32:]

        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

        pad_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-pad_length]

        decrypted_filename = f"{filename}_decrypted.txt"
        with open(decrypted_filename, 'wb') as f:
            f.write(decrypted_data)

        logging.info(f"Decrypted file: {filename}")
        messagebox.showinfo("Success", f"The file has been decrypted successfully and saved as: {decrypted_filename}")

    except Exception as e:
        logging.error(f"Error during decryption: {str(e)}")
        messagebox.showerror("Error", f"Error during decryption: {str(e)}")

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SafeFileEncryptor")
        self.root.geometry("500x400")
        self.root.configure(bg="#2b2b2b")

        self.style = ttk.Style()
        self.style.configure("TFrame", background="#2b2b2b")
        self.style.configure("TLabel", background="#2b2b2b", foreground="#ffffff", font=("Arial", 12))
        self.style.configure("TButton", background="#444444", foreground="#000000", font=("Arial", 12), padding=6)
        self.style.map("TButton", background=[('active', '#555555')])
        self.style.configure("TEntry", fieldbackground="#444444", foreground="#000000", font=("Arial", 12))

        self.frame = ttk.Frame(self.root, padding="20")
        self.frame.pack(expand=True, fill="both")

        self.label = ttk.Label(self.frame, text="Enter a password for encryption/decryption:")
        self.label.pack(pady=15)

        self.password_entry = ttk.Entry(self.frame, show="*")
        self.password_entry.pack(pady=10, ipadx=5, ipady=5)

        self.encrypt_button = ttk.Button(self.frame, text="Encrypt a file", command=self.encrypt_file)
        self.encrypt_button.pack(pady=15, ipadx=10, ipady=10)

        self.decrypt_button = ttk.Button(self.frame, text="Decrypt a file", command=self.decrypt_file)
        self.decrypt_button.pack(pady=15, ipadx=10, ipady=10)

        self.quit_button = ttk.Button(self.frame, text="Quit", command=self.root.quit)
        self.quit_button.pack(pady=10, ipadx=10, ipady=10)

    def encrypt_file(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required.")
            return

        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            encrypt_file(filename, password)

    def decrypt_file(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Password is required.")
            return

        filename = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        if filename:
            decrypt_file(filename, password)

def run_app():
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

if __name__ == "__main__":
    run_app()
