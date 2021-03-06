import inspect
import requests
from utils import normalizeData, stringifyNormalizedData
from signer import sign
from verifier import verify
from kparser import parseAuthorizationHeader
from functools import wraps


def generateAuthorization(header_values: dict, method: str, path: str, headers: list, keyId: str, privateKey: str, hash: str, algorithm: str, hide_algorithm: bool = True):
    """ 
    Generate Authorization

    This function create an Authorization header with the given value and configuration

    Parameters:   
    header_values (dict): A dictionary containing every header and it value  
    method (str): The http method used for the request  
    path (str): The path of the request (without host)  
    headers (list<str>): The list of headers to use in the signature  
    keyId (str): The key identifier  
    privateKey (str): The private key value linked to the keyId  
    hash (str): The hash algorithm to use (sha256 or sha512)  
    algorithm (str): The cryptographic algorithm to use (rsa, dsa or ecdsa)  
    hide_algorithm (bool): When true the used algorithm won't be in the generated header, 'hs2019' will be used instead and the server will choose the algorithm according the the keyId  

    Returns: 
    str: Value of the Authorization header 

    """
    normalized = normalizeData(header_values, method, path, headers)
    stringified = stringifyNormalizedData(normalized)
    signature = sign(stringified, privateKey, hash, algorithm)
    return 'Signature keyId="' + keyId + '",algorithm="' + ('hs2019' if hide_algorithm else (algorithm + '-' + hash)) + '",headers="' + ' '.join([str.lower(h) for h in headers]) + '",signature="' + signature + '"'


def verifyAuthorization(header_values: dict, method: str, path: str, headers: list, keyId: str, publicKey: str, hash: str, algorithm: str, signature: str):
    """ 
    Verify Authorization

    This function verify the components of an Authorization header with the given value and configuration
    Those components are given by the parseAuthorizationHeader function

    Parameters:   
    header_values (dict): A dictionary containing every header and it value  
    method (str): The http method used for the request  
    path (str): The path of the request (without host)  
    headers (list<str>): The list of headers to use in the signature  
    keyId (str): The key identifier  
    publicKey (str): The public key value linked to the keyId  
    hash (str): The hash algorithm to use (sha256 or sha512)  
    algorithm (str): The cryptographic algorithm to use (rsa, dsa or ecdsa)  
    signature (str): The signature given in the header

    Returns: 
    bool: True if the components match the signature

    """
    normalized = normalizeData(header_values, method, path, headers)
    stringified = stringifyNormalizedData(normalized)
    return verify(stringified, signature, publicKey, hash, algorithm)
