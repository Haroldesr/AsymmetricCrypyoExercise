# hybrid_encrypt.py
import os, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def load_public_key(path="keys/public_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def hybrid_encrypt(plaintext: bytes):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    pub = load_public_key()
    enc_key = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    package = {
        "enc_key": base64.b64encode(enc_key).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }
    return package

if __name__ == "__main__":
    with open("sample_plain.txt", "rb") as f:
        pt = f.read()
    pkg = hybrid_encrypt(pt)
    with open("encrypted_package.json", "w", encoding="utf-8") as jf:
        json.dump(pkg, jf, indent=2)
    print("Paquete cifrado guardado en encrypted_package.json")
    print("Contenido (parcial):")
    print("enc_key:", pkg["enc_key"][:60], "...")
