import os
import base64
import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def browse_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt_decrypt_file():
    file_path = file_entry.get()
    password = password_entry.get().encode()
    salt = salt_entry.get().encode()

    if not file_path or not password or not salt:
        return

    key = generate_key(password, salt)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    if operation_var.get() == "encrypt":
        encrypted_data = fernet.encrypt(data)
        output_path = os.path.splitext(file_path)[0] + "_encrypted" + os.path.splitext(file_path)[1]
    elif operation_var.get() == "decrypt":
        encrypted_data = fernet.decrypt(data)
        output_path = os.path.splitext(file_path)[0] + "_decrypted" + os.path.splitext(file_path)[1]

    with open(output_path, 'wb') as output_file:
        output_file.write(encrypted_data)

root = tk.Tk()
root.title("Image Encryptor/Decryptor")

operation_var = tk.StringVar()
operation_var.set("encrypt")

  
file_entry = tk.Entry(root, width=40)
file_entry.grid(row=0, column=0, padx=10, pady=10)

browse_button = tk.Button(root, text="Browse", command=browse_file)
browse_button.grid(row=0, column=1, padx=10, pady=10)

password_label = tk.Label(root, text="Password:")
password_label.grid(row=1, column=0, sticky="w", padx=10)

password_entry = tk.Entry(root, show="*", width=40)
password_entry.grid(row=2, column=0, padx=10, pady=10)

salt_label = tk.Label(root, text="Salt:")
salt_label.grid(row=3, column=0, sticky="w", padx=10)

salt_entry = tk.Entry(root, width=40)
salt_entry.grid(row=4, column=0, padx=10, pady=10)

encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=operation_var, value="encrypt")
encrypt_radio.grid(row=5, column=0, padx=10, pady=10)

decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=operation_var, value="decrypt")
decrypt_radio.grid(row=6, column=0, padx=10, pady=10)

execute_button = tk.Button(root, text="Execute", command=encrypt_decrypt_file)
execute_button.grid(row=7, column=0, padx=10, pady=10)

root.mainloop()