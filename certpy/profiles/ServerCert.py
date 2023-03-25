from .EndEntityCert import EndEntityCert

class ServerCert(EndEntityCert):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)

        # Extended Key Usage
        self.server_auth = True
