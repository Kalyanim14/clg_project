import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
from encrypt import encrypt_message
from decrypt import decrypt_message
import os

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

# Create the main window with a clean theme
app = ttk.Window(themename="flatly")  # You can try "litera", "minty", "pulse" etc.
app.title("🔐 Image Message Encryptor & Decryptor")
app.geometry("700x600")  # Initial size
app.minsize(600, 500)     # Let it resize
app.resizable(True, True)

ttk.Label(app, text="🔐 Secure Image Encryptor & Decryptor", font=("Segoe UI", 18, "bold"), bootstyle="info").pack(pady=15)

# ========== Encryption Frame ==========
frame1 = ttk.LabelFrame(app, text="Encrypt Message", padding=20, bootstyle="info")
frame1.pack(padx=20, pady=10, fill=BOTH, expand=True)

enc_img_path = ttk.StringVar()
ttk.Label(frame1, text="Select Image:", font=("Segoe UI", 11)).grid(row=0, column=0, sticky=W, pady=5)
ttk.Entry(frame1, textvariable=enc_img_path, width=45).grid(row=0, column=1, padx=10, pady=5)
ttk.Button(frame1, text="Browse", command=lambda: browse_file(enc_img_path), bootstyle="secondary-outline").grid(row=0, column=2, pady=5)

ttk.Label(frame1, text="Secret Message:", font=("Segoe UI", 11)).grid(row=1, column=0, sticky=W, pady=10)
enc_msg = ttk.Entry(frame1, width=50)
enc_msg.grid(row=1, column=1, columnspan=2, pady=5)

ttk.Label(frame1, text="Password:", font=("Segoe UI", 11)).grid(row=2, column=0, sticky=W, pady=10)
enc_pwd = ttk.Entry(frame1, width=50, show="*")
enc_pwd.grid(row=2, column=1, columnspan=2, pady=5)

ttk.Button(frame1, text="Encrypt Message", command=do_encrypt, bootstyle="success-outline").grid(row=3, column=1, pady=20)

# ========== Decryption Frame ==========
frame2 = ttk.LabelFrame(app, text="Decrypt Message", padding=20, bootstyle="warning")
frame2.pack(padx=20, pady=10, fill=BOTH, expand=True)

dec_img_path = ttk.StringVar()
ttk.Label(frame2, text="Encrypted Image:", font=("Segoe UI", 11)).grid(row=0, column=0, sticky=W, pady=5)
ttk.Entry(frame2, textvariable=dec_img_path, width=45).grid(row=0, column=1, padx=10, pady=5)
ttk.Button(frame2, text="Browse", command=lambda: browse_file(dec_img_path), bootstyle="secondary-outline").grid(row=0, column=2, pady=5)

ttk.Label(frame2, text="Password:", font=("Segoe UI", 11)).grid(row=1, column=0, sticky=W, pady=10)
dec_pwd = ttk.Entry(frame2, width=50, show="*")
dec_pwd.grid(row=1, column=1, columnspan=2, pady=5)

# ✅ Added Missing Decrypt Button
ttk.Button(frame2, text="Decrypt Image", command=do_decrypt, bootstyle="primary-outline").grid(row=2, column=1, pady=20)

app.mainloop()
