#!/usr/bin/env python3

import warnings

import re
import os
import ssl
import ipaddress

from hashlib import sha256
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID as EKU
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh, ec, rsa
from cryptography.hazmat.primitives.hashes import SHA256

from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat

PEM = Encoding.PEM
PKCS3 = ParameterFormat.PKCS3
TraditionalOpenSSL = PrivateFormat.TraditionalOpenSSL

YEAR = (365.2425*86400)

def _get_caller():
    try:
        import inspect
        from pathlib import Path
        return Path(inspect.stack()[-1].filename).resolve()
    except:
        return None

_caller = _get_caller()

def _lenpfx(s):
    if isinstance(s, bytes):
        pass
    elif isinstance(s, str):
        s = s.encode()
    else:
        s = str(s).encode()
    return len(s).to_bytes(8, byteorder='big') + s

_warned_cachedir = False
def _cachedir(filename):
    global _warned_cachedir
    try:
        from pathlib import Path
        from appdirs import user_cache_dir

        cachedir = Path(user_cache_dir(), 'pyselfcert')
        cachedir.mkdir(mode=0o750, parents=True, exist_ok=True)
        return Path(cachedir, filename)
    except ImportError:
        if not _warned_cachedir:
            _warned_cachedir = True
            warnings.warn("Please install the Python3 `appdirs` module to save certificates to cachedir!")
        return Path(filename).resolve()

def _get_cert_location(identifier, name, algo, keysize):
    msg = b''.join(map(_lenpfx, (identifier, name, algo, keysize)))
    sha = sha256(msg).hexdigest()
    filename = f'.{sha}.tls.pem'
    return _cachedir(filename)

def _dh():
    dh_file = _cachedir('.dh2048.pem')
    if dh_file.is_file():
        return str(dh_file)
    else:
        warnings.warn('Generating Diffie-Hellman parameters, this may take a moment...')
        p = dh.generate_parameters(2, 2048, default_backend())
        with open(dh_file, 'wb') as f:
            dh_param = p.parameter_bytes(PEM, PKCS3)
            f.write(dh_param)
            return str(dh_file)

    return None

def _load(filename):
    from OpenSSL.crypto import FILETYPE_PEM, load_certificate, load_privatekey
    cert_begin = '-----BEGIN CERTIFICATE-----'
    cert_end = '-----END CERTIFICATE-----'
    certs = []
    with open(filename, 'r') as f:
        pem = f.read()
        key = load_privatekey(FILETYPE_PEM, pem)
        begin = 0
        while True:
            begin = pem.find(cert_begin, begin)
            if begin < 0: break
            end = pem.find(cert_end, begin+len(cert_begin))
            if end < 0: break
            end += len(cert_end)
            certs.append(load_certificate(FILETYPE_PEM, pem[begin:end]))
            begin = end

    return (key, certs[0], certs[1:])


def _create_context(filename, type_):
    from OpenSSL.crypto import TYPE_EC, TYPE_RSA

    if type_ == 'pem':
        return open(filename, 'r').read()
    elif type_ == 'flask':
        return (filename, filename)
    elif type_ == 'twisted':
        from twisted.python.filepath import FilePath
        from twisted.internet.ssl import CertificateOptions, TLSVersion
        from twisted.internet.ssl import DiffieHellmanParameters

        key, cert, chain = _load(filename)

        # we don't need dhparams if the key is ecdsa
        if cert.get_pubkey().type() in [TYPE_EC]:
            dh = None
        else:
            dh = DiffieHellmanParameters(FilePath(_dh()))

        return CertificateOptions(
            privateKey=key,
            certificate=cert,
            extraCertChain=chain,
            raiseMinimumTo=TLSVersion.TLSv1_2,
            dhParameters=dh,
        )
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(filename)

        _, cert, _ = _load(filename)
        if cert.get_pubkey().type() not in [TYPE_EC]:
            context.load_dh_params(_dh())

        return context

def get_context(identifier=None, name=None, algo='ecdsa256', type_=None, filename=None):
    if filename is not None:
        if identifier is not None or name is not None or algo is not None:
            raise Exception('identifier, name, and/or algo not supported with filename')
        return _create_context(filename, type_)

    if identifier is None:
        identifier = _caller

    m = re.fullmatch(r'(rsa|ecdsa)[_-]?([1-9][0-9]+)?', algo.lower())
    if m is None:
        raise ValueError(f'Invalid algorithm string `{algo}` specified!')
    else:
        algo = m.group(1)
        keysize = int(m.group(2) or 0)

    if algo == 'ecdsa':
        if not keysize: keysize = 256
        if keysize == 256:
            key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        elif keysize == 384:
            key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        elif keysize == 521:
            key = ec.generate_private_key(ec.SECP521R1(), default_backend())
        else:
            raise ValueError(f'Invalid key size `{keysize}` specified for ECDSA!')
    elif algo == 'rsa':
        if not keysize: keysize = 2048
        if keysize >= 2048 and keysize <= 15360 and keysize % 512 == 0:
            key = rsa.generate_private_key(65537, keysize, default_backend())
        else:
            raise ValueError(f'Invalid key size `{keysize}` specified for RSA!')

    filename = _get_cert_location(identifier, name, algo, keysize)

    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        return _create_context(filename, type_)

    subj = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f'Development Certificate ({identifier})')
    ])

    if name is None:
        names = list(map(x509.DNSName, ['localhost', '127.0.0.1']))
        addr4s = list(map(x509.IPAddress, map(ipaddress.ip_address, ['127.0.0.1'])))
        net4s = list(map(x509.IPAddress, map(ipaddress.ip_network, ['127.0.0.1/32'])))
    else:
        names = [name]
        addr4s = []
        net4s = []

    pub = key.public_key()
    crt = x509.CertificateBuilder().public_key(pub)

    # basics
    crt = crt.subject_name(subj)
    crt = crt.issuer_name(subj)
    crt = crt.serial_number(1)
    crt = crt.not_valid_before(datetime.now() - timedelta(seconds=60))
    crt = crt.not_valid_after(datetime.now() + timedelta(seconds=int(50*YEAR)))
    crt = crt.add_extension(x509.SubjectAlternativeName(names + addr4s), False)

    # Enable (Digital Signature, Key Agreement, Certificate Sign)
    crt = crt.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
    crt = crt.add_extension(x509.ExtendedKeyUsage([EKU.SERVER_AUTH]), False)

    crt = crt.add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), False)
    crt = crt.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pub), False)
    crt = crt.add_extension(x509.NameConstraints(names + net4s, None), False)
    crt = crt.add_extension(x509.BasicConstraints(ca=True, path_length=0), True)

    # sign the cert
    crt = crt.sign(key, SHA256(), default_backend())

    with open(os.open(filename, os.O_CREAT | os.O_WRONLY, 0o640), 'wb') as f:
        f.write(key.private_bytes(
            encoding=PEM,
            format=TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        ))
        f.write(crt.public_bytes(encoding=PEM))

    return _create_context(filename, type_)

if __name__ == '__main__':
    get_context()
