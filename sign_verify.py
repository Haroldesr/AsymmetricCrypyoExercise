# sign_verify.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from getpass import getpass

PASS = getpass("Introduce la passphrase para la clave privada: ").encode()

def load_private_key(path="keys/private_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=PASS)

def load_public_key(path="keys/public_key.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign_message(message: bytes):
    priv = load_private_key()
    signature = priv.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_message(message: bytes, signature: bytes):
    pub = load_public_key()
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

if __name__ == "__main__":
    msg = b"Mensaje de prueba para firmar desde VS Code"
    sig = sign_message(msg)
    print("Firma (hex parcial):", sig.hex()[:80], "...")
    print("Verificacion:", verify_message(msg, sig))
