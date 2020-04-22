from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import base64

def sign(data: str, private_key: str, hash: str, algorithm: str):
    bkey = private_key.encode() if type(private_key) == str else private_key
    key = load_pem_private_key(bkey, password=None, backend=default_backend())
    if hash == 'sha256':
        hasher = SHA256()
    elif hash == 'sha512':
        hasher = SHA512()
    else:
        raise ValueError("Invalid hash value (should be sha256 or sha512)")

    if algorithm == 'ecdsa':
        sig = key.sign(data.encode(), ec.ECDSA(algorithm=hasher))
    else:
        sig = key.sign(data.encode(), PKCS1v15(), hasher)
        
    return base64.b64encode(sig).decode()