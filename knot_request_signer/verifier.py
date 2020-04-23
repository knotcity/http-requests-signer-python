from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.hashes import SHA256, SHA512
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.exceptions import InvalidSignature

import base64

def verify(data: str, sig: str, publicKey: str, hash: str, algorithm: str):
    bkey = publicKey.encode() if type(publicKey) == str else publicKey
    key = load_pem_public_key(bkey, backend=default_backend())

    if hash == 'sha256':
        hasher = SHA256()
    elif hash == 'sha512':
        hasher = SHA512()
    else:
        raise ValueError("Invalid hash value (should be sha256 or sha512)")
    
    signature = base64.b64decode(sig)

    try:
        if algorithm == 'ecdsa':
            key.verify(signature, data.encode(), ec.ECDSA(algorithm=hasher))
        else:
            key.verify(signature, data.encode(), PKCS1v15(), hasher)
    except(InvalidSignature):
        return False
    return True
