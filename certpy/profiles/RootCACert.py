from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import HashAlgorithm, SHA256

from ..util import CertBase

class RootCACert(CertBase):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)
        self.ca = True
        self.pathlen = 0

        # key usages
        self.key_cert_sign = True

    def sign(self, *, hash_algo=SHA256, duration=None, not_before=None, not_after=None):
        # check arguments
        if not issubclass(hash_algo, HashAlgorithm):
            raise TypeError('hash_algo must be a subclass of HashAlgorithm')

        crt = self.build(None, self.key, duration, not_before, not_after)

        return crt.sign(self.key, hash_algo(), default_backend())
