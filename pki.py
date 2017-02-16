import dht
import engine
import sodium
import bencode

class Storeable(object):
    def bencode(self, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def bdecode(self, data):
        raise NotImplementedError()

    @classmethod
    def load(cls, filename):
        with open(filename, "r") as f:
            return cls.bdecode(f.read())

    def save(self, filename, **kwargs):
        data = self.bencode(**kwargs)
        with open(filename, "w") as f:
            f.write(data)

class Certificate(Storeable):
    def __init__(self, ip, pk, sk, sig):
        self.ip = ip
        self.pk = pk
        self.sk = sk
        self.sig = sig

    def bencode(self, with_secret=True, with_signature=True):
        data = {}
        data["ip"] = self.ip
        data["pk"] = self.pk
        if with_secret and self.sk:
            data["sk"] = self.sk
        if with_signature and self.sig:
            data["sig"] = self.sig
        return bencode.bencode(data)

    @staticmethod
    def bdecode(data):
        data = bencode.bdecode(data)
        ip = data["ip"]
        pk = data["pk"]
        sk = data.get("sk", None)
        sig = data.get("sig", None)
        return Certificate(ip, pk, sk, sig)

    @staticmethod
    def generate(ip):
        pk, sk = sodium.crypto_sign_keypair()
        return Certificate(ip, pk, sk, None)

    @property
    def public(self):
        data = self.bencode(with_secret=False, with_signature=True)
        return Certificate.bdecode(data)

    def open_message(self, msg):
        return sodium.crypto_sign_open(msg, self.pk)

    def sign_message(self, msg):
        if not self.sk: return None
        return sodium.crypto_sign(msg, self.sk)


class Authority(Storeable):
    def __init__(self, subnet, pk, sk):
        self.subnet = subnet
        self.pk = pk
        self.sk = sk

    def bencode(self, with_secret=True):
        data = {}
        data["subnet"] = {}
        data["subnet"]["ip"] = self.subnet[0]
        data["subnet"]["cidr"] = self.subnet[1]
        data["pk"] = self.pk
        if with_secret and self.sk:
            data["sk"] = self.sk
        return bencode.bencode(data)

    @staticmethod
    def bdecode(data):
        data = bencode.bdecode(data)
        subnet = (data["subnet"]["ip"], data["subnet"]["cidr"])
        return Authority(subnet, data["pk"], data.get("sk", None))

    @staticmethod
    def generate(subnet):
        pk, sk = sodium.crypto_sign_keypair()
        return Authority(subnet, pk, sk)

    @property
    def public(self):
        data = self.bencode(with_secret=False)
        return Authority.bdecode(data)

    def sign_certificate(self, cert):
        if not self.sk: return False
        data = cert.bencode(with_secret=False, with_signature=False)
        cert.sig = sodium.crypto_sign_detached(data, self.sk)
        return True

    def verify_certificate(self, cert):
        if not cert.sig: return False
        data = cert.bencode(with_secret=False, with_signature=False)
        return sodium.crypto_sign_verify_detached(cert.sig, data, self.pk)
