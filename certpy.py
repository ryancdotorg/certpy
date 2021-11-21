#!/usr/bin/env python3

import warnings

import re
import os
import abc
import ssl
import argparse
import ipaddress
import functools

from hashlib import sha256
from datetime import datetime, timedelta
from collections.abc import Iterable


from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

# land mines, dragons, and dinosaurs with laser guns
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

PEM = Encoding.PEM
PKCS3 = ParameterFormat.PKCS3
TraditionalOpenSSL = PrivateFormat.TraditionalOpenSSL
OCSP = x509.oid.AuthorityInformationAccessOID.OCSP
CA_ISSUERS = x509.oid.AuthorityInformationAccessOID.CA_ISSUERS

YEAR = (365.2425*86400)

def isiterable(x):
    return not isinstance(x, (str, bytes)) and isinstance(x, Iterable)

def memoize(fn):
    decorator = getattr(functools, 'cache', None)
    if decorator is not None: return decorator(fn)
    # fallback for Python < 3.9
    else: return functools.lru_cache(maxsize=None)(fn)

def cached_property(fn):
    decorator = getattr(functools, 'cached_property', None)
    if decorator is not None: return decorator(fn)
    # fallback for Python < 3.8
    else: return property(functools.lru_cache()(fn))

def mapable(fn):
    def wrapped(first, *args, **kwarg):
        if len(args) > 0:
            return wrapped((first,) + args, **kwarg)
        elif isiterable(first) and len(args) == 0:
            return map(lambda x: fn(x, **kwarg), first)
        elif len(args) == 0:
            return fn(first, **kwarg)
        else:
            raise TypeError('Unexpected positional argument(s)!')

    return wrapped

def mapped(fn, *args):
    mapper = mapable(fn)
    return list(mapper(*args))

def foreach(fn, first, *args):
    if len(args) > 0:
        foreach(fn, (first,) + args)
    elif isiterable(first) and len(args) == 0:
        for item in first: fn(item)
    elif len(args) == 0:
        fn(first)
    else:
        raise TypeError('Unexpected positional argument(s)!')

# helper functions
def camel_to_snake(name):
  name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
  return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()

@mapable
def x509_ip(ip):
    return x509.IPAddress(ipaddress.ip_address(ip))

@mapable
def x509_net(net):
    return x509.IPAddress(ipaddress.ip_network(net))

@mapable
def x509_dns(dns):
    return x509.DNSName(dns)

@mapable
def x509_uri(uri):
    return x509.UniformResourceIdentifier(uri)

@mapable
def x509_host(host, force_dns_name=False):
    if force_dns_name:
        return x509_dns(host)
    else:
        try:
            return x509_ip(host)
        except ValueError:
            try:
                return x509_net(host)
            except ValueError:
                return x509_dns(host)

class NameAttributes:
    def __init__(self):
        self.attribs = {}

    def __len__(self):
        return len(self.attribs)

    def __getattr__(self, key):
        uc = key.upper()
        if hasattr(NameOID, uc):
            return self.attribs.get(uc, None)

    def __setattr__(self, key, value):
        uc = key.upper()
        if hasattr(NameOID, uc):
            oid = getattr(NameOID, uc)
            self.attribs[uc] = x509.NameAttribute(oid, value)
        else:
            object.__setattr__(self, key, value)

    def __delattr__(self, key):
        uc = key.upper()
        if hasattr(NameOID, uc):
            self.attribs.pop(uc, None)

    def output(self):
        return x509.Name(list(self.attribs.values()))

class SANs:
    def __init__(self, include_ips_as_dns_names=True):
        self.include_ips_as_dns_names = include_ips_as_dns_names
        self.hosts, self.ips = [], []

    def __len__(self):
        return len(self.hosts) + len(self.ips)

    def _encode(self, san):
        try:
            item = x509_ip(san)
            if include_ips_as_dns_names:
                alt = x509_dns(san)
                return ((self.ips, item), (self.hosts, alt))
            else:
                return ((self.ips, item),)
        except ValueError:
            item = x509_dns(san)
            return ((self.hosts, item),)

    def add(self, san):
        for items, encoded in self._encode(san):
            items.append(encoded)

    def remove(self, san):
        for items, encoded in self._encode(san):
            items.remove(encoded)

    def discard(self, san):
        for items, encoded in self._encode(san):
            if encoded in items:
                items.remove(encoded)

    def __contains__(self, san):
        for items, encoded in self._encode(san):
            if encoded not in items: return False

        return True

    def output(self):
        return x509.SubjectAlternativeName(self.hosts + self.ips)

class PrivateKeyAlgorithm(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __call__(self, *args, **kwarg): return

class ED25519(PrivateKeyAlgorithm):
    def __call__(self):
        return ed25519.Ed25519PrivateKey.generate()

class ED448(PrivateKeyAlgorithm):
    def __call__(self):
        return ed448.Ed448PrivateKey.generate()



### RSA
@mapable
def rsa_factory(bits, *args, backend=default_backend, public_exponent=65537):
    if bits < 2048 or bits > 15360 or bits % 512 != 0:
        raise ValueError(f'Invalid key size `{bits}`!')

    def generate(self, public_exponent=public_exponent):
        return rsa.generate_private_key(public_exponent, bits, backend())

    return type(f'RSA{bits}', (PrivateKeyAlgorithm,), {
        '__call__': generate,
    })()

key_sizes = (2048, 3072, 4096)
RSA2048, RSA3072, RSA4096 = rsa_factory(key_sizes)

### ECDSA
@mapable
def ecdsa_factory(curve, *args, backend=default_backend):
    curve = curve()
    if not isinstance(curve, ec.EllipticCurve):
        raise ValueError(f'Invalid curve `{type(curve)}`!')

    return type(curve.__class__.__name__, (PrivateKeyAlgorithm,), {
        '__call__': lambda self: ec.generate_private_key(curve, backend()),
    })()

curves = (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)
SECP256R1, SECP384R1, SECP521R1 = ecdsa_factory(curves)

eku_oids = []
for eku in dir(ExtendedKeyUsageOID):
    if eku[0] != '_':
        k, v = eku.lower(), getattr(ExtendedKeyUsageOID, eku)
        eku_oids.append((k, v))

'''
name_oids = []
for name in dir(NameOID):
    if name[0] != '_':
        k, v = name.lower(), NameOID[k]
        name_oids.append((k, v))
'''

class CertAttribs:
    def __init__(self, key_algo=SECP256R1, *args, **kwarg):
        super().__init__(*args, **kwarg)
        if not isinstance(key_algo, PrivateKeyAlgorithm):
            raise TypeError('key_algo must be an instance of PrivateKeyAlgorithm')

        self.key_algo = key_algo
        self.subject = NameAttributes()

        self.ca = False
        self.pathlen = None

        self.crl_distribution_points = []
        self.crl_issuer = None
        self.ocsp_responders = []
        self.ca_issuers = []
        self.permitted_subtrees = []
        self.excluded_subtrees = []

        usages = (
            'digital_signature', 'content_commitment', 'key_encipherment',
            'data_encipherment', 'key_agreement', 'key_cert_sign',
            'crl_sign', 'encipher_only', 'decipher_only'
        )
        for usage in usages: setattr(self, usage, False)
        for k, _ in eku_oids: setattr(self, k, False)

    def _extended_key_usage(self):
        ekus = []
        for k, v in eku_oids:
            if getattr(self, k):
                ekus.append(v)

        return x509.ExtendedKeyUsage(ekus)

    def _key_usage(self):
        return x509.KeyUsage(
            self.digital_signature, self.content_commitment, self.key_encipherment,
            self.data_encipherment, self.key_agreement, self.key_cert_sign,
            self.crl_sign, self.encipher_only, self.decipher_only
        )

    def _basic_constraints(self):
        pathlen = self.pathlen if self.ca else None
        return x509.BasicConstraints(ca=self.ca, path_length=pathlen)

    def sign(self, ca, key, *, hash_algo=SHA256, duration=None, not_before=None, not_after=None):
        # check arguments
        if all(map(lambda x: x is not None, (duration, not_before, not_after))):
            raise ValueError('At least one of (`duration`, `not_before`, `not_after`) must be None!')

        if not issubclass(hash_algo, HashAlgorithm):
            raise TypeError('hash_algo must be a subclass of HashAlgorithm')

        # figure out start time
        if not_before is None:
            if duration is not None and not_after is not None:
                not_before = not_after - duration
            else:
                not_before = datetime.now() - timedelta(seconds=60)

        # figure out expiry time
        if not_after is None:
            if duration is not None:
                not_after = not_before + duration
            else:
                not_after = datetime.now() + timedelta(seconds=int(1*YEAR))

        if ca is not None:
            try:
                ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
                aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski.value)
            except x509.ExtensionNotFound:
                aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
        else:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())

        crt = x509.CertificateBuilder()
        crt = crt.public_key(self.pub)
        crt = crt.subject_name(self.subject.output())
        crt = crt.issuer_name(ca.subject if ca else self.subject.output())
        crt = crt.serial_number(x509.random_serial_number())
        crt = crt.not_valid_before(not_before)
        crt = crt.not_valid_after(not_after)
        crt = crt.add_extension(x509.SubjectKeyIdentifier.from_public_key(self.pub), False)
        crt = crt.add_extension(aki, False)
        crt = crt.add_extension(self._key_usage(), True)
        crt = crt.add_extension(self._extended_key_usage(), False)
        crt = crt.add_extension(self._basic_constraints(), not self.ca)

        if len(self.crl_distribution_points) > 0:
            full_namess = map(x509.UniformResourceIdentifier, self.crl_distribution_points)

            crt = crt.add_extension(x509.CRLDistributionPoints(
                [x509.DistributionPoint(full_names, None, self.crl_issuer, None)]
            ), False)

        if len(self.ocsp_responders) > 0 or len(self.ca_issuers) > 0:
            descriptions = []

            for uri in self.ocsp_responders:
                descriptions.append(x509.AccessDescription(OCSP, x509_uri(uri)))

            for uri in self.ca_issuers:
                descriptions.append(x509.AccessDescription(CA_ISSUERS, x509_uri(uri)))

            crt = crt.add_extension(x509.AuthorityInformationAccess(descriptions), False)

        if self.ca:
            permitted = None
            if len(self.permitted_subtrees) > 0:
                permitted = mapped(x509_host, self.permitted_subtrees)

            excluded = None
            if len(self.excluded_subtrees) > 0:
                excluded = mapped(x509_host, self.excluded_subtrees)

            if permitted is not None or excluded is not None:
                crt.add_extension(x509.NameConstraints(permitted, excluded), True)

        if len(self.sans):
            crt = crt.add_extension(self.sans.output(), not bool(len(self.subject)))

        return crt.sign(key, hash_algo(), default_backend())

    def output(self, builder):
        builder.public_key(self.pub)

    # The non_repudiation key usage was renamed to content_commitment
    def __getattr__(self, key):
        if key == 'non_repudiation': return self.content_commitment
        elif key == 'content_commitment': return self.non_repudiation

    @property
    def pub(self): return self.key.public_key()


class CACert(CertAttribs):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)
        self.ca = True
        self.pathlen = 0
        # key usages
        self.key_cert_sign = True

class OCSPSignerCert(CertAttribs):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)
        self.key_cert_sign = True

class CRLSignerCert(CertAttribs):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)

class ServerCert(CertAttribs):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)
        self.ca = False
        self.pathlen = None
        # RSA keys can be used for key agreement (but probably shouldn't)
        if isinstance(self.pub, rsa.RSAPublicKey):
            self.key_agreement = True
        self.digital_signature = True
        self.server_auth = True
        self.sans = SANs()

class SelfSignedServerCert(ServerCert, CACert):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)
        self.ca = True
        self.pathlen = 0


if __name__ == '__main__':
    c = SelfSignedServerCert(RSA2048)
    c.sans.add('example.com')
    c.subject.common_name = 'certificate'
    print(c.pub)
    signed = c.sign(None, c.key)
    print(signed.public_bytes(encoding=PEM).decode())
