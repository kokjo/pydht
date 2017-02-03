import socket
import time
import struct
import hashlib

def xor(x, y):
    return "".join(chr(ord(a) ^ ord(b)) for a,b in zip(x, y))

class Node(object):
    def __init__(self, contact, id):
        self.contact = contact
        self.id = id
        self.last_ping = int(time.time())

    def __str__(self):
        return self.id + encode_addr(self.contact)

    def __repr__(self):
        return "<Node %s %s>" % (self.id.encode("hex"), self.contact[0])

    def __eq__(self, other):
        return self.id == other.id

    def __hash__(self):
        return hash(self.id)

def random(size):
    with open("/dev/urandom", "r") as urand:
        return urand.read(size)

def p32(n):
    return struct.pack("<L", n)

def decode_addr(s):
    assert len(s) == 6
    ip = ".".join(str(ord(c)) for c in s[:4])
    port = struct.unpack(">H", s[4:6])[0]
    return (ip, port)

def encode_addr(addr):
    ip, port = addr
    ip = "".join(chr(int(i)) for i in ip.split("."))
    port = struct.pack(">H", port)
    return ip+port

def decode_addrs(s):
    l = []
    while s:
        l.append(decode_addr(s[:6]))
        s = s[6:]
    return l

def encode_addrs(addrs):
    s = ""
    for addr in addrs:
        s += encode_addr

def decode_node(s):
    assert len(s) == 26
    id = s[:20]
    addr = decode_addr(s[20:26])
    return Node(addr, id)

def encode_node(node):
    return node.id + encode_addr(node.contact)

def decode_nodes(s):
    l = [] 
    while s:
        l.append(decode_node(s[:26]))
        s = s[26:]
    return l

def encode_nodes(nodes):
    return "".join(encode_node(node) for node in nodes)


def sha1(data):
    return hashlib.sha1(data).digest()

def get_txnid(size=4):
    return random(size)

def get_bootstrap_addr():
    return (socket.gethostbyaddr("router.bittorrent.com")[2][0], 6881)
