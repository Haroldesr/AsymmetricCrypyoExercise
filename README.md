Ejemplo sencillo de cifrado asimétrico, firmado digital y cifrado híbrido usando Python. 

El ejercicio incluye:

- Generación de claves pública y privada
- Firma y verificación digital
- Cifrado y descifrado híbrido (RSA + AES)
- Archivos de ejemplo para ejecutar cada proceso

¿Cómo usar el proyecto?

1. Generar las claves
Ejecuta:

python generate_keys.py

Esto creará la carpeta keys/ con:
public_key.pem
private_key.pem

2. Firmar y verificar un mensaje
Ejecuta:

python sign_verify.py

El programa:
- Firma el contenido de message.txt
- Verifica la firma
- Muestra el resultado en la consola

3. Cifrado híbrido (RSA + AES)
Para cifrar ejecuta:

python hybrid_encrypt.py

Esto genera:
- encrypted_package.json
El cual contiene la clave AES cifrada, el IV y el mensaje cifrado.

Para descifrar ejecuta:

python hybrid_decrypt.py

Esto lee encrypted_package.json y muestra el mensaje descifrado.

