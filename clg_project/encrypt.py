import cv2
import os

def encrypt_message(image_path, output_path, message, password):
    img = cv2.imread(image_path)
    if img is None:
        return "Error: Could not open image."

    d = {chr(i): i for i in range(255)}
    n, m, z = 0, 0, 0
    msg_length = len(message)
    img[0, 0] = [msg_length, 0, 0]

    for i, char in enumerate(message):
        n, m = divmod(i + 1, img.shape[1])
        img[n, m, z] = d.get(char, 0)
        z = (z + 1) % 3

    if not output_path.lower().endswith(('.png', '.jpg', '.jpeg')):
        output_path += '.png'

    success = cv2.imwrite(output_path, img)
    if not success or not os.path.exists(output_path):
        return "Error: Failed to save encrypted image."

    try:
        with open("password.txt", "w") as f:
            f.write(password)
    except Exception as e:
        return f"Error writing password: {e}"

    return None
