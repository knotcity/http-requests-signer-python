import inspect
from utils import normalizeData, stringifyNormalizedData
from signer import sign
from verifier import verify
from functools import wraps  

def generateAuthorization(header_values: dict, method: str, path: str, headers: list, keyId: str, privateKey: bytes, hash: str, algorihtm: str):
    """ 
    Generate Authorization
  
    This function create an Authorization header with the given value and configuration
  
    Parameters:   
    header_values (dict): A dictionary containing every header and it value  
    method (str): The http method used for the request  
    path (str): The path of the request (without host)  
    headers (list<string>): The list of headers to use in the signature  
    keyId (string): The key identifier  
    privateKey (string): The private key value linked to the keyId  
    hash (string): The hash algorithm to use (sha256 or sha512)  
    algorithm (string): The cryptographic algorihtm to use (rsa, dsa or ecdsa)  
  
    Returns: 
    string: Value of the Authorization header 
  
    """
    normalized = normalizeData(header_values, method, path, headers)
    stringified = stringifyNormalizedData(normalized)
    signature = sign(stringified, privateKey, hash, algorihtm)
    print(signature)
    ver = verify(stringified, signature, pubKey, hash, algorihtm)
    print(ver)

privKey = ('-----BEGIN PRIVATE KEY-----\n'
    'MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAxfrhuLtAvLjB7rLX\n'
    'DvGT67B2ro4c9xy+SKJi0GQsH8k5fY7pmLqbjaeb/rbQeeEMHCUUDeHwkHcIN4EF\n'
    '+qyIKM+hgYkDgYYABAFXcbiq2ZT4ZP46KEM/mwZko1AxTPDg0DS3YXg8OIupenZs\n'
    'I7VrarW6L2DBE5+LEyVxwFptoSAM/Dd9bIn01IYSHQBB6Pxtn3cRs0GnSYPP2TRR\n'
    'z63I+X0sim2p4O8BSBo5RnotmiteYM1XXlotdRPM0WzmM/Y8gU/mmsR7QsJt9OSs\n'
    'cQ==\n'
    '-----END PRIVATE KEY-----\n')
pubKey = ('-----BEGIN PUBLIC KEY-----\n'
    'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBV3G4qtmU+GT+OihDP5sGZKNQMUzw\n'
    '4NA0t2F4PDiLqXp2bCO1a2q1ui9gwROfixMlccBabaEgDPw3fWyJ9NSGEh0AQej8\n'
    'bZ93EbNBp0mDz9k0Uc+tyPl9LIptqeDvAUgaOUZ6LZorXmDNV15aLXUTzNFs5jP2\n'
    'PIFP5prEe0LCbfTkrHE=\n'
    '-----END PUBLIC KEY-----\n')
generateAuthorization({
    "test":True,
    "yep": 1,
    "another": "test",
    "lit": ["val1", "val2"]
}, 'GET', '/test', ['test', 'yep', 'another', 'lit'], 
'testKeyid', privKey, 'sha256', 'ecdsa')
