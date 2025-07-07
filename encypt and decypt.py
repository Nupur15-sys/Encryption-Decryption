import os
from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # AES block size


# Padding for AES block alignment
def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


# Encrypt file with AES-256
def encrypt_file(file_path, password):
    try:
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=32, count=1000000)
        cipher = AES.new(key, AES.MODE_CBC)
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        padded_data = pad(plaintext)
        ciphertext = cipher.encrypt(padded_data)
        with open(file_path + '.enc', 'wb') as f:
            f.write(salt + cipher.iv + ciphertext)
        messagebox.showinfo("Success", "Encryption successful.\nSaved as: " + file_path + ".enc")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{e}")


# Decrypt file with AES-256
def decrypt_file(file_path, password):
    try:
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            iv = f.read(16)
            ciphertext = f.read()
        key = PBKDF2(password, salt, dkLen=32, count=1000000)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext)
        new_path = file_path.replace('.enc', '') + '_decrypted'
        with open(new_path, 'wb') as f:
            f.write(plaintext)
        messagebox.showinfo("Success", "Decryption successful.\nSaved as: " + new_path)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{e}")


# GUI Functions
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, END)
        entry_file.insert(0, file_path)


def start_encryption():
    file_path = entry_file.get()
    password = entry_password.get()
    if not file_path or not password:
        messagebox.showwarning("Missing Info", "Please select a file and enter a password.")
        return
    encrypt_file(file_path, password)


def start_decryption():
    file_path = entry_file.get()
    password = entry_password.get()
    if not file_path or not password:
        messagebox.showwarning("Missing Info", "Please select a file and enter a password.")
        return
    decrypt_file(file_path, password)


# GUI Setup
app = Tk()
app.title("AES-256 File Encryption & Decryption")
app.geometry("500x220")
app.resizable(False, False)

Label(app, text="Select File:", font=("Arial", 11)).pack(pady=5)
entry_file = Entry(app, width=55)
entry_file.pack()
Button(app, text="Browse", command=browse_file).pack(pady=5)

Label(app, text="Enter Password:", font=("Arial", 11)).pack(pady=5)
entry_password = Entry(app, show="*", width=30)
entry_password.pack()

frame_buttons = Frame(app)
frame_buttons.pack(pady=15)

Button(frame_buttons, text="Encrypt File", width=20, command=start_encryption).grid(row=0, column=0, padx=10)
Button(frame_buttons, text="Decrypt File", width=20, command=start_decryption).grid(row=0, column=1, padx=10)

app.mainloop()
