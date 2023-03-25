from .ServerCert import ServerCert
from .RootCACert import RootCACert

class SelfSignedServerCert(ServerCert, RootCACert):
    def __init__(self, *args, **kwarg):
        super().__init__(*args, **kwarg)

        # No, really, this is a CA
        self.ca = True
        self.pathlen = 0
