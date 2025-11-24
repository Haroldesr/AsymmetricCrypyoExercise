# hybrid_decrypt.py
import base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from getpass import getpass

PASS = getpass("Introduce la passphrase para la clave privada: ").encode()

def load_private_key(path="keys/private_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=PASS)

def hybrid_decrypt(package_path="encrypted_package.json"):
    with open(package_path, "r", encoding="utf-8") as jf:
        pkg = json.load(jf)

    enc_key = base64.b64decode(pkg["enc_key"])
    nonce = base64.b64decode(pkg["nonce"])
    ciphertext = base64.b64decode(pkg["ciphertext"])

    priv = load_private_key()
    aes_key = priv.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext

if __name__ == "__main__":
    pt = hybrid_decrypt()
    print("Mensaje descifrado:")
    print(pt.decode('utf-8'))
