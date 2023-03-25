from ..util import CertBase

# Mix-in
class CRLSignerCert(CertBase):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)
        self.crl_sign = True
