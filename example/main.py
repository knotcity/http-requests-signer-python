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

headers = {
    "test": 'True',
    "yep": '1',
    "another": "test",
    "lit": "val1"
}

authorization = generateAuthorization(headers, 'GET', '/test', ['(request-target)','test', 'yep', 'another', 'lit'], 'testKeyid', privKey, 'sha256', 'ecdsa')
print(authorization)
headers['Authorization'] = authorization

resp = requests.get('http://localhost:8080/test', headers=headers)
print(resp)

keyId, header_list, hash, algorithm, signature = parseAuthorizationHeader(authorization)
print(verifyAuthorization(headers, 'GET', '/test', header_list, keyId, pubKey, hash, algorithm, signature))
