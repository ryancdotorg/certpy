from ..util import CertBase

# Mix-in
class OCSPSignerCert(CertBase):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)
        self.key_cert_sign = True
        self.ocsp_signing = True
