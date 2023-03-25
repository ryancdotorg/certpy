from .EndEntityCert import EndEntityCert

class ClientCert(EndEntityCert):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)

        # Extended Key Usage
        self.client_auth = True
