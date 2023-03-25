from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512

class CertBase:
    def __init__(self, pub=None, key=None, *args, **kwarg):
        super().__init__(*args, **kwarg)

        self._pub = pub
        self.key = key

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
                from sys import stderr
                print('eku', k, v, file=stderr)
                ekus.append(v)

        print(ekus, file=stderr)
        return x509.ExtendedKeyUsage(ekus) if len(ekus) else None

    def _key_usage(self):
        return x509.KeyUsage(
            self.digital_signature, self.content_commitment, self.key_encipherment,
            self.data_encipherment, self.key_agreement, self.key_cert_sign,
            self.crl_sign, self.encipher_only, self.decipher_only
        )

    def _basic_constraints(self):
        pathlen = self.pathlen if self.ca else None
        return x509.BasicConstraints(ca=self.ca, path_length=pathlen)

    def build(self, ca=None, key=None, duration=None, not_before=None, not_after=None):
        # check arguments
        if all(map(lambda x: x is not None, (duration, not_before, not_after))):
            raise ValueError('At least one of (`duration`, `not_before`, `not_after`) must be None!')

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
                # See https://support.apple.com/en-us/HT210176
                not_after = datetime.now() + timedelta(days=820)

        if ca is not None:
            try:
                ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
                aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski.value)
            except x509.ExtensionNotFound:
                aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())
        else:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key())

        if len(self.sans.emails) > 0:
            self.email_protection = True

        crt = x509.CertificateBuilder()
        crt = crt.public_key(self.pub)
        crt = crt.subject_name(self.subject.output())
        crt = crt.issuer_name(ca.subject if ca else self.subject.output())
        crt = crt.serial_number(x509.random_serial_number())
        crt = crt.not_valid_before(not_before)
        crt = crt.not_valid_after(not_after)
        crt = crt.add_extension(x509.SubjectKeyIdentifier.from_public_key(self.pub), False)
        crt = crt.add_extension(aki, False)
        #crt = crt.add_extension(self._key_usage(), True)
        #eku = self._extended_key_usage()
        #if eku is not None:
        #    crt = crt.add_extension(eku, False)
        crt = crt.add_extension(self._basic_constraints(), True)

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

        return crt

    def sign(self, ca, key, *, hash_algo=SHA256, duration=None, not_before=None, not_after=None):
        # check arguments
        if not issubclass(hash_algo, HashAlgorithm):
            raise TypeError('hash_algo must be a subclass of HashAlgorithm')

        crt = self.build(ca, key, duration, not_before, not_after)

        return crt.sign(key, hash_algo(), default_backend())

    def output(self, builder):
        builder.public_key(self.pub)

    # The non_repudiation key usage was renamed to content_commitment
    def __getattr__(self, key):
        if key == 'non_repudiation': return self.content_commitment
        elif key == 'content_commitment': return self.non_repudiation

    @property
    def pub(self):
        return self._pub if self._pub else self.key.public_key()

    @pub.setter
    def pub(self, value):
        self.key = None
        self._pub = value
