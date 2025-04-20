import socket
import threading
import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography import exceptions

# --- Funciones Auxiliares ---

def b64encode_bytes(data):
    return base64.b64encode(data).decode('utf-8')

def b64decode_bytes(data):
    return base64.b64decode(data.encode('utf-8'))


# --- Manejo de Mensajes ---

# Función para recibir mensajes
def receive_messages(sock, key):
    while True:
        try:
            message = sock.recv(1024)
            if message:
                msg = json.loads(message)
                iv = b64decode_bytes(msg["iv"])
                ct = b64decode_bytes(msg["ct"])
                tag = b64decode_bytes(msg["tag"])
                try:
                    mac = hmac.HMAC(key, hashes.SHA256())
                    mac.update(ct)
                    mac.verify(tag)
                    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
                    unpadder = padding.PKCS7(128).unpadder()
                    pt = unpadder.update(padded_plaintext) + unpadder.finalize()
                    print("[Otro cliente] " + pt.decode())
                except exceptions.InvalidSignature as e:
                    print(f"La seguridad se vió comprometida")
                    sock.close()
                    return
        except:
            break

def main():
    host = 'localhost'
    port = 12345

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    print("Conectado al servidor. Puedes comenzar a enviar mensajes.")

    # Protocolo signal
    message = client.recv(1024).decode()
    derived_key = None

    # Bob
    if message == "Bob":
        # Envio de llaves
        IKB = os.urandom(32)
        SPKB = os.urandom(32)
        sign = Ed25519PrivateKey.from_private_bytes(IKB).sign(SPKB)
        keys = {
                "IKB": b64encode_bytes(IKB),
                "SPKB": b64encode_bytes(SPKB),
                "sign": b64encode_bytes(sign)
            }
        client.send(json.dumps(keys).encode())

        # Recibo de llaves
        message = client.recv(1024).decode()
        keys = json.loads(message)
        IKA = b64decode_bytes(keys["IKA"])
        EKA = b64decode_bytes(keys["EKA"])
        AD = b64decode_bytes(keys["AD"])
        iv = b64decode_bytes(keys["iv"])

        # Diffie-Hellman
        dh1 = X25519PrivateKey.from_private_bytes(IKA).exchange(X25519PrivateKey.from_private_bytes(SPKB).public_key())
        dh2 = X25519PrivateKey.from_private_bytes(EKA).exchange(X25519PrivateKey.from_private_bytes(IKB).public_key())
        dh3 = X25519PrivateKey.from_private_bytes(EKA).exchange(X25519PrivateKey.from_private_bytes(SPKB).public_key())
        derived_key = HKDF(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=None,
                            info=b'handshake data',
                        ).derive(dh1 + dh2 + dh3)
        
        # Data asociada
        encryptor = Cipher(algorithms.AES(derived_key), modes.CBC(iv)).encryptor()
        AD_prime = encryptor.update(IKA + IKB) + encryptor.finalize()

        # Verificar data asociada
        if AD != AD_prime:
            print(f"La seguridad se vió comprometida")
            client.close()
            return
        
    
    # Alice
    else: 
        # Recibo de llaves
        keys = json.loads(message)
        IKB = b64decode_bytes(keys["IKB"])
        SPKB = b64decode_bytes(keys["SPKB"])
        sign = b64decode_bytes(keys["sign"])

        try:
            # Verificar firma
            Ed25519PrivateKey.from_private_bytes(IKB).public_key().verify(sign, SPKB)

            # Creación de llaves
            IKA = os.urandom(32)
            EKA = os.urandom(32)

            # Diffie-Hellman
            dh1 = X25519PrivateKey.from_private_bytes(IKA).exchange(X25519PrivateKey.from_private_bytes(SPKB).public_key())
            dh2 = X25519PrivateKey.from_private_bytes(EKA).exchange(X25519PrivateKey.from_private_bytes(IKB).public_key())
            dh3 = X25519PrivateKey.from_private_bytes(EKA).exchange(X25519PrivateKey.from_private_bytes(SPKB).public_key())
            derived_key = HKDF(
                                algorithm=hashes.SHA256(),
                                length=32,
                                salt=None,
                                info=b'handshake data',
                            ).derive(dh1 + dh2 + dh3)
            
            # Data asociada
            iv = os.urandom(16)
            encryptor = Cipher(algorithms.AES(derived_key), modes.CBC(iv)).encryptor()
            AD = encryptor.update(IKA + IKB) + encryptor.finalize()

            # Envio de llaves
            keys = {
                "IKA": b64encode_bytes(IKA),
                "EKA": b64encode_bytes(EKA),
                "AD": b64encode_bytes(AD),
                "iv": b64encode_bytes(iv)
            }
            client.send(json.dumps(keys).encode())

        except exceptions.InvalidSignature as e:
            print(f"La seguridad se vió comprometida")
            client.close()
            return

    # Hilo para recibir mensajes
    threading.Thread(target=receive_messages, args=(client, derived_key), daemon=True).start()

    # Enviar mensajes
    while True:
        msg = input()
        if msg.lower() == "salir":
            break

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(msg.encode()) + padder.finalize()

        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(derived_key), modes.CBC(iv)).encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        mac = hmac.HMAC(derived_key, hashes.SHA256())
        mac.update(ct)
        tag = mac.finalize()
        message = {
                    "iv": b64encode_bytes(iv),
                    "ct": b64encode_bytes(ct),
                    "tag": b64encode_bytes(tag)
                    }
        client.send(json.dumps(message).encode())

    client.close()

if __name__ == "__main__":
    main()
