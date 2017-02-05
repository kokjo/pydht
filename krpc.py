from udpserver import UDPServer
from bencode import bencode, bdecode
from engine import *
from collections import Counter
from utils import *

class UnsupportedMethod(Exception): pass

class RequestFailed(Exception): pass

class Transaction(object):
    def __init__(self):
        self.callback = None
        self.result = None

    def __repr__(self):
        return "<Txn done:%r>" % (self.done)

    @property
    def done(self): return self.result != None

    def set_result(self, res):
        self.result = res
        if self.callback: self.callback(self)

class KRPC(UDPServer):
    def __init__(self, *args, **kwargs):
        UDPServer.__init__(self, *args, **kwargs)
        self.supported_methods = []
        self.transactions = {}
        self.ip_vote = Counter()
        self.ip_vote[self.bind[0]] += 1
        self.engine.add_interval(60, self.reset_ip)

    def reset_ip(self):
        self.ip_vote = Counter()
        self.ip_vote[self.bind[0]] += 1

    def send_packet(self, data, addr):
        if addr[0] in self.ip_vote.keys(): return
        UDPServer.send_packet(self, data, addr)

    def send_krpc(self, req, addr, timeout=5):
        txnid = get_txnid(4)
        req["t"] = txnid
        req["v"] = "YOLO"

        txn = Transaction()
        txn.addr = addr
        txn.txnid = txnid
        self.transactions[txnid] = txn

        data = bencode(req)
        self.send_packet(data, addr)

        self.engine.add_timeout(5, lambda : self.timeout_transaction(txnid))

        return txn

    def timeout_transaction(self, txnid):
        if txnid in self.transactions:
            del self.transactions[txnid]

    def make_request(self, addr, met, **kwargs):
        req = {"y":"q", "q":met, "a":kwargs}
        return self.send_krpc(req, addr)

    def handle_packet(self, data, addr):
        try:
            data = bdecode(data)
            if "ip" in data:
                addr = decode_addr(data["ip"])
                self.ip_vote[addr[0]] += 1
            if data.get("y") == "r":
                self.handle_response(data, addr)
            if data.get("y") == "q":
                self.handle_request(data, addr)
#            if data.get("y") == "e":
#                self.handle_error(data, addr)
        except ValueError:
            print "Invalid packet. Dropping"

#    def handle_error(self, data, addr):
#        pass

    def handle_response(self, data, addr):
        txn_id = data.get("t", "")
        txn = self.transactions.pop(txn_id, None)
        if txn: txn.set_result(data["r"])

    def handle_request(self, data, addr):
        met = data["q"]
        if met not in self.supported_methods:
            return
        try:
            func = getattr(self, "request_" + met)
            resp = {}
            resp["y"] = "r"
            resp["t"] = data["t"]
            resp["r"] = func(data["a"], addr)
            resp["ip"] = encode_addr(addr)
            data = bencode(resp)
            self.send_packet(data, addr)
        except AttributeError:
            raise UnsupportedMethod(met, data, addr)

if __name__ == "__main__":
    eng = Engine()
    serv = KRPC(eng, bind=("0.0.0.0", 1337))
    eng.start()
