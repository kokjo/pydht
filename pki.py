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

def parse_subnet(subnet):
    ip, cidr = subnet.split("/", 1)
    return (ip, int(cidr))

def create_authority(name, subnet):
    subnet = parse_subnet(subnet)
    auth_sec = Authority.generate(subnet)
    print "[*] Certificate authority generate"
    auth_pub = auth_sec.public
    auth_sec.save("%s.sec" % name)
    auth_pub.save("%s.pub" % name)
    print "[+] Certificate authority saved"

def open_authotiry(name):
    try:
        auth = Authority.load("%s.sec" % name)
        print "[+] Opened %s.sec" % name
        return auth
    except IOError:
        pass
    try:
        auth = Authority.load("%s.pub" % name)
        print "[+] Opened %s.pub" % name
        return auth
    except IOError:
        print "[-] Could not opne certificate authority"
        return None

def view_authority(name):
    auth = open_authotiry(name)
    if not auth: return
    print "[*] Subnet: %s/%d" % auth.subnet
    print "[*] Public key: %s" % auth.pk.encode("hex")
    if auth.sk:
        print "[*] Secret key: %s" % auth.sk.encode("hex")

def create_certificate(name, ip, auth=None):
    cert_sec = Certificate.generate(ip)
    print "[*] Certificate generate"
    if auth:
        auth = Authority.load("%s.sec" % auth)
        auth.sign_certificate(cert_sec)
        print "[*] Certificate signed"
    cert_pub = cert_sec.public
    cert_sec.save("%s.key" % name)
    cert_pub.save("%s.cert" % name)
    print "[*] Certificate saved"

def open_certificate(name):
    try:
        cert = Certificate.load("%s.key" % name)
        print "[+] Opned %s.key" % name
        return cert
    except IOError:
        pass
    try:
        cert = Certificate.load("%s.cert" % name)
        print "[+] Opned %s.cert" % name
        return cert
    except IOError:
        print "[-] Could not opne certificate"
        return None

def view_certificate(name):
    cert = open_certificate(name)
    if not cert: return
    print "[*] ip: %s" % cert.ip
    print "[*] Public key: %s" % cert.pk.encode("hex")
    if cert.sk:
        print "[*] Secret key: %s" % cert.sk.encode("hex")
    if cert.sig:
        print "[*] Signature: %s" % cert.sig.encode("hex")

def verify_certificate(cert, auth):
    cert = open_certificate(cert)
    auth = open_authotiry(auth)
    if not (cert and auth): return
    if auth.verify_certificate(cert):
        print "[+] Certificate valid"
    else:
        print "[-] Certificate invalid"

commands = {
    "create_ca": create_authority,
    "view_ca": view_authority,
    "create_cert": create_certificate,
    "view_cert": view_certificate,
    "verify_cert": verify_certificate
}

if __name__ == "__main__":
    import sys
    commands[sys.argv[1]](*sys.argv[2:])
