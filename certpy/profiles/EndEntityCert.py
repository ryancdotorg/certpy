from cryptography.hazmat.primitives.asymmetric import rsa

from ..util import CertBase, SANs

class EndEntityCert(CertBase):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)

        # Basic Constraints
        self.ca = False
        self.pathlen = None

        # Basic Key Usage
        self.digital_signature = True
        if isinstance(self.pub, rsa.RSAPublicKey):
            # RSA keys can be used for key encipherment (but shouldn't)
            self.key_encipherment = True

        # Subject Alternative Names
        self.sans = SANs()
