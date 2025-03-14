import cv2
import os

def decrypt_message(image_path, entered_password):
    if not os.path.exists(image_path):
        return "Error: Encrypted image file not found."

    img = cv2.imread(image_path)
    if img is None:
        return "Error: Could not open or find the image."

    c = {i: chr(i) for i in range(255)}

    try:
        with open("password.txt", "r") as f:
            stored_password = f.read().strip()
    except FileNotFoundError:
        return "Error: Password file not found."

    if entered_password != stored_password:
        return "YOU ARE NOT AUTHORIZED!"

    msg_length = img[0, 0, 0]
    n, m, z = 0, 0, 0
    message = ""

    for i in range(msg_length):
        n, m = divmod(i + 1, img.shape[1])
        message += c[img[n, m, z]]
        z = (z + 1) % 3

    return message
