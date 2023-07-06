#!/usr/bin/env python3

import sys

from certpy.util import SECP256R1, PEM, PKCS8, NoEncryption
from certpy.profiles import SelfSignedServerCert

if __name__ == '__main__':
    k = SECP256R1()
    c = SelfSignedServerCert(key=k)
    c.sans.add(f'192.168.4.1')
    cn = 'GL.iNet GL-AR750S'
    if len(sys.argv) > 2:
        cn += f' ({sys.argv[2]})'
    c.subject.common_name = cn
    signed = c.sign()

    # Print private key (if available)
    print(c.key.private_bytes(PEM, PKCS8, NoEncryption()).decode().strip())

    # Print certifiate
    print(signed.public_bytes(encoding=PEM).decode().strip())
