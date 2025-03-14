import tkinter as tk
from tkinter import filedialog, messagebox
from encrypt import encrypt_message
from decrypt import decrypt_message
import os

# === Reusable Functions ===
def browse_file(var):
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
    var.set(file_path)

def do_encrypt():
    img_path = enc_img_path.get()
    msg = enc_msg.get()
    pwd = enc_pwd.get()

    if not img_path or not msg or not pwd:
        messagebox.showwarning("Missing Info", "Please fill all encryption fields.")
        return

    output_file = "encrypted_" + os.path.basename(img_path)
    error = encrypt_message(img_path, output_file, msg, pwd)

    if error:
        messagebox.showerror("Encryption Failed", error)
    else:
        messagebox.showinfo("Success", f"Message encrypted and saved as:\n{output_file}")

def do_decrypt():
    img_path = dec_img_path.get()
    pwd = dec_pwd.get()

    if not img_path or not pwd:
        messagebox.showwarning("Missing Info", "Please fill all decryption fields.")
        return

    result = decrypt_message(img_path, pwd)
    if result.startswith("Error") or result == "YOU ARE NOT AUTHORIZED!":
        messagebox.showerror("Decryption Failed", result)
    else:
        messagebox.showinfo("Decrypted Message", f"Message:\n{result}")

# === Main App Window ===
root = tk.Tk()
root.title("Secure Image Encryptor/Decryptor")
root.geometry("500x450")
root.resizable(False, False)
root.configure(bg="#f0f4f7")

title = tk.Label(root, text="Image Encryptor & Decryptor", font=("Helvetica", 18, "bold"), bg="#f0f4f7", fg="#333")
title.pack(pady=15)

# === Frame: Encryption ===
encrypt_frame = tk.LabelFrame(root, text="Encrypt Message", padx=10, pady=10, bg="#f9fcff", font=("Arial", 11, "bold"))
encrypt_frame.pack(padx=20, pady=10, fill="both")

enc_img_path = tk.StringVar()
tk.Label(encrypt_frame, text="Image Path:", bg="#f9fcff").grid(row=0, column=0, sticky="w")
tk.Entry(encrypt_frame, textvariable=enc_img_path, width=40).grid(row=0, column=1, padx=5)
tk.Button(encrypt_frame, text="Browse", command=lambda: browse_file(enc_img_path)).grid(row=0, column=2)

tk.Label(encrypt_frame, text="Secret Message:", bg="#f9fcff").grid(row=1, column=0, sticky="w", pady=5)
enc_msg = tk.Entry(encrypt_frame, width=40)
enc_msg.grid(row=1, column=1, columnspan=2, pady=5)

tk.Label(encrypt_frame, text="Password:", bg="#f9fcff").grid(row=2, column=0, sticky="w")
enc_pwd = tk.Entry(encrypt_frame, width=40, show="*")
enc_pwd.grid(row=2, column=1, columnspan=2, pady=5)

tk.Button(encrypt_frame, text="Encrypt", command=do_encrypt, bg="#4CAF50", fg="white", width=20).grid(row=3, column=1, pady=10)

# === Frame: Decryption ===
decrypt_frame = tk.LabelFrame(root, text="Decrypt Message", padx=10, pady=10, bg="#f9fcff", font=("Arial", 11, "bold"))
decrypt_frame.pack(padx=20, pady=10, fill="both")

dec_img_path = tk.StringVar()
tk.Label(decrypt_frame, text="Encrypted Image:", bg="#f9fcff").grid(row=0, column=0, sticky="w")
tk.Entry(decrypt_frame, textvariable=dec_img_path, width=40).grid(row=0, column=1, padx=5)
tk.Button(decrypt_frame, text="Browse", command=lambda: browse_file(dec_img_path)).grid(row=0, column=2)

tk.Label(decrypt_frame, text="Password:", bg="#f9fcff").grid(row=1, column=0, sticky="w")
dec_pwd = tk.Entry(decrypt_frame, width=40, show="*")
dec_pwd.grid(row=1, column=1, columnspan=2, pady=5)

tk.Button(decrypt_frame, text="Decrypt", command=do_decrypt, bg="#2196F3", fg="white", width=20).grid(row=2, column=1, pady=10)

root.mainloop()
