import streamlit as st
from Crypto.Cipher import Blowfish, DES
from tinyec import registry
from Crypto.Util.Padding import pad, unpad
import secrets
import numpy as np


# Function for Blowfish Encryption/Decryption
def encrypt_blowfish(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_plaintext = pad(plaintext.encode("utf-8"), Blowfish.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext


def decrypt_blowfish(ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_data, Blowfish.block_size)
    return plaintext.decode("utf-8")


# Function for Caesar Cipher Encryption/Decryption
def encrypt_caesar(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            shifted_char = chr(
                (ord(char) - ord("A" if is_upper else "a") + shift) % 26
                + ord("A" if is_upper else "a")
            )
            result += shifted_char
        else:
            result += char
    return result


def decrypt_caesar(ciphertext, shift):
    return encrypt_caesar(ciphertext, -shift)


# Function for DES Encryption/Decryption
def encrypt_des(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode("utf-8"), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext


def decrypt_des(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_data, DES.block_size)
    return plaintext.decode("utf-8")


# Function for ECC (Elliptic Curve Cryptography) Key Exchange
def ecc_key_exchange():
    curve = registry.get_curve("brainpoolP256r1")
    Ka = secrets.randbelow(curve.field.n)
    X = Ka * curve.g
    Kb = secrets.randbelow(curve.field.n)
    Y = Kb * curve.g
    A_SharedKey = Ka * Y
    B_SharedKey = Kb * X
    return (
        f"A shared key: {compress(A_SharedKey)}",
        f"B shared key: {compress(B_SharedKey)}",
    )


# Function for Hill Cipher Encryption/Decryption
def encrypt_hill_cipher(message, key):
    keyMatrix = np.array(
        [[ord(k) % 65 for k in key[i : i + 3]] for i in range(0, 9, 3)]
    )
    messageVector = np.array([[ord(message[i]) % 65] for i in range(3)])
    cipherMatrix = np.dot(keyMatrix, messageVector) % 26
    return "".join([chr(cipherMatrix[i][0] + 65) for i in range(3)])


def decrypt_hill_cipher(ciphertext, key):
    keyMatrix = np.array(
        [[ord(k) % 65 for k in key[i : i + 3]] for i in range(0, 9, 3)]
    )
    inverse_key = np.linalg.inv(keyMatrix) % 26
    ciphertextVector = np.array([[ord(ciphertext[i]) % 65] for i in range(3)])
    decryptedMatrix = np.dot(inverse_key, ciphertextVector) % 26
    return "".join([chr(decryptedMatrix[i][0] + 65) for i in range(3)])


# Function for Playfair Cipher Encryption/Decryption
def playfair_cipher(message, key):
    key = key.replace(" ", "")
    key = key.upper()
    # Rest of the Playfair Cipher implementation...


# Function for Vigenere Encryption/Decryption
def encrypt_vigenere(plaintext, keyword):
    result = ""
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[
        : len(plaintext)
    ]

    for i in range(len(plaintext)):
        char = plaintext[i]
        if char.isalpha():
            is_upper = char.isupper()
            shifted_char = chr(
                (
                    ord(char)
                    - ord("A" if is_upper else "a")
                    + ord(keyword_repeated[i])
                    - ord("A")
                )
                % 26
                + ord("A" if is_upper else "a")
            )
            result += shifted_char
        else:
            result += char

    return result


def decrypt_vigenere(ciphertext, keyword):
    decrypted_text = encrypt_vigenere(
        ciphertext,
        "".join(
            [
                chr((26 - ord(k) + ord("A")) % 26 + ord("A")) if k.isalpha() else k
                for k in keyword
            ]
        ),
    )
    return decrypted_text


# Streamlit App
def main():
    st.title("Encryption and Decryption App")

    # User chooses the encryption/decryption algorithm
    algorithm = st.selectbox(
        "Choose Algorithm",
        [
            "Blowfish",
            "Caesar Cipher",
            "DES",
            "ECC Key Exchange",
            "Hill Cipher",
            "Playfair Cipher",
            "Vigenere",
        ],
    )

    # User inputs text
    plaintext = st.text_area("Enter Text")

    if algorithm not in ["ECC Key Exchange", "Playfair Cipher"]:
        # Generate a random key for algorithms other than ECC and Playfair Cipher
        key = st.text_input("Enter Key")

    if algorithm == "Blowfish":
        # Encrypt the plaintext
        cipher_text = encrypt_blowfish(plaintext, key)
        st.subheader("Encrypted Text:")
        st.write(cipher_text.hex())

        # Decrypt the ciphertext
        decrypted_text = decrypt_blowfish(cipher_text, key)
        st.subheader("Decrypted Text:")
        st.write(decrypted_text)

    elif algorithm == "Caesar Cipher":
        # User inputs shift amount
        shift_amount = st.slider("Select Shift Amount", -25, 25, 0)

        # Encrypt the plaintext
        cipher_text = encrypt_caesar(plaintext, shift_amount)
        st.subheader("Encrypted Text:")
        st.write(cipher_text)

        # Decrypt the ciphertext
        decrypted_text = decrypt_caesar(cipher_text, shift_amount)
        st.subheader("Decrypted Text:")
        st.write(decrypted_text)

    elif algorithm == "DES":
        # Encrypt the plaintext
        cipher_text = encrypt_des(plaintext, key)
        st.subheader("Encrypted Text:")
        st.write(cipher_text.hex())

        # Decrypt the ciphertext
        decrypted_text = decrypt_des(cipher_text, key)
        st.subheader("Decrypted Text:")
        st.write(decrypted_text)

    elif algorithm == "ECC Key Exchange":
        result_A, result_B = ecc_key_exchange()
        st.subheader("Key Exchange Result:")
        st.write(result_A)
        st.write(result_B)

    elif algorithm == "Hill Cipher":
        # User inputs the 3x3 key matrix
        key_matrix = st.text_area("Enter 3x3 Key Matrix (e.g., ABCDEF...):")

        # Encrypt the plaintext
        cipher_text = encrypt_hill_cipher(plaintext, key_matrix)
        st.subheader("Encrypted Text:")
        st.write(cipher_text)

        # Decrypt the ciphertext
        decrypted_text = decrypt_hill_cipher(cipher_text, key_matrix)
        st.subheader("Decrypted Text:")
        st.write(decrypted_text)

    elif algorithm == "Playfair Cipher":
        # User inputs the key for Playfair Cipher
        playfair_key = st.text_input("Enter Key")

        # Implement Playfair Cipher logic...

    elif algorithm == "Vigenere":
        # User inputs the keyword for Vigenere Cipher
        keyword_vigenere = st.text_input("Enter Keyword")

        # Encrypt the plaintext
        cipher_text = encrypt_vigenere(plaintext, keyword_vigenere)
        st.subheader("Encrypted Text:")
        st.write(cipher_text)

        # Decrypt the ciphertext
        decrypted_text = decrypt_vigenere(cipher_text, keyword_vigenere)
        st.subheader("Decrypted Text:")
        st.write(decrypted_text)


# Run the Streamlit app
if __name__ == "__main__":
    main()
