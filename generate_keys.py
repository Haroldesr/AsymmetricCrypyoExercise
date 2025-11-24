# generate_keys.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
from getpass import getpass

os.makedirs("keys", exist_ok=True)

# Pedimos passphrase de manera segura
passphrase = getpass("Ingrese passphrase para cifrar la clave privada (se ocultará): ").encode()

# Generar clave privada RSA (3072 bits recomendado)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072
)

# Serializar clave privada (cifrada con passphrase)
pem_priv = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(passphrase)
)

with open("keys/private_key.pem", "wb") as f:
    f.write(pem_priv)

# Serializar clave pública
public_key = private_key.public_key()
pem_pub = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open("keys/public_key.pem", "wb") as f:
    f.write(pem_pub)

print("Claves generadas en la carpeta keys/ (private_key.pem está cifrada).")
