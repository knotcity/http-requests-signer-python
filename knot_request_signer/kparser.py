import re
from utils import validateAlgorithm

def parseAuthorizationHeader(auth: str):
    """ 
    Parse Authorization

    This function parse an Authorization header and return its components

    Parameters:   
    auth (str): The authorization header value

    Returns: 

    """
    try:
        fspace = auth.index(' ')
    except(ValueError):
        raise ValueError(
            "Given authorization header is not valid, could not find the space between 'Signature' and the other parts of the header")

    fword = auth[:fspace]
    remaining = auth[fspace+1:]
    if str.lower(fword) != 'signature':
        raise ValueError(
            "Given authorization header do not start with Signature")

    parts = re.split(',(?!(?=[^"]*"[^"]*(?:"[^"]*"[^"]*)*$))', remaining)
    for p in parts:
        try:
            eqIdx = p.index('=')
        except(ValueError):
            raise ValueError(
                "Given authorization header is not valid, missing an equal sign in '" + p + "'")
        key = p[:eqIdx]
        value = p[eqIdx+1:]
        if len(value) < 2 or value[0] != '"' or value[-1] != '"':
            raise ValueError("Given authorization header is not valid, value should be quoted with double quotes in '" + p + "'")
        value = value[1:-1]
        if key == 'keyId':
            keyId = value
        elif key == 'algorithm':
            algorithm, hash = validateAlgorithm(value)
        elif key == 'headers':
            headers = value.split(' ')
        elif key == 'signature':
            signature = value
        else:
            raise ValueError("Given authorization header is not valid, invalid key found in '" + p + "'")

    return keyId, headers, hash, algorithm, signature
