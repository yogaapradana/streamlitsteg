# === Steganography Universal Encoder-Decoder Prototype ===
# Requires: pip install streamlit cryptography stegano opencv-python numpy

import streamlit as st
from cryptography.fernet import Fernet
from stegano import lsb
import base64
import os
import tempfile
import mimetypes

# Utility: Generate key from password (simplified, not production-ready)
def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(password.encode('utf-8').ljust(32, b'0'))

# Encryption
def encrypt_file(file_data: bytes, password: str) -> bytes:
    key = generate_key(password)
    f = Fernet(key)
    return f.encrypt(file_data)

# Decryption
def decrypt_file(file_data: bytes, password: str) -> bytes:
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(file_data)

# Embedding file into image using LSB
def embed_file_in_image(image_file, secret_file_data, output_path):
    secret_b64 = base64.b64encode(secret_file_data).decode('utf-8')
    secret_text = f"[FILE]{secret_b64}"
    secret_image_path = lsb.hide(image_file, secret_text)
    secret_image_path.save(output_path)

# Extract file from image
def extract_file_from_image(image_file, password):
    message = lsb.reveal(image_file)
    if not message or not message.startswith("[FILE]"):
        return None
    try:
        encrypted_data = base64.b64decode(message[6:].encode('utf-8'))
        return decrypt_file(encrypted_data, password)
    except:
        return None
    
# Streamlit UI
st.title("🔐 Universal Steganography Encoder/Decoder Prototype")
st.markdown("Prototype v1: Text/File -> Image, secure, WhatsApp-compatible")

mode = st.radio("Choose mode:", ["Encode file to image", "Decode file from image"])

if mode == "Encode file to image":
    cover_image = st.file_uploader("Upload cover image (PNG recommended)", type=['png'])
    secret_file = st.file_uploader("Upload secret file (any type)")
    password = st.text_input("Encryption password", type="password")

    if st.button("🔒 Encode") and cover_image and secret_file and password:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as temp_cover:
            temp_cover.write(cover_image.read())
            temp_cover_path = temp_cover.name

        encrypted_data = encrypt_file(secret_file.read(), password)

        output_path = temp_cover_path.replace(".png", "_secret.png")
        embed_file_in_image(temp_cover_path, encrypted_data, output_path)

        with open(output_path, "rb") as out_file:
            st.success("File encoded successfully!")
            st.download_button("📥 Download Encoded Image", data=out_file, file_name="stego_image.png")

elif mode == "Decode file from image":
    stego_image = st.file_uploader("Upload image with hidden file", type=['png'])
    password = st.text_input("Decryption password", type="password")

    if st.button("🔓 Decode") and stego_image and password:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as temp_stego:
            temp_stego.write(stego_image.read())
            temp_stego_path = temp_stego.name

        recovered_data = extract_file_from_image(temp_stego_path, password)

        if recovered_data:
            st.success("Secret file recovered!")
            st.download_button("📂 Download Secret File", data=recovered_data, file_name="recovered_file")
        else:
            st.error("Failed to recover file. Check password or file integrity.")