import engine
from krpc import *
from routingtable import *
from infohashtable import *
from collections import Counter
import logging

logging.basicConfig(level=logging.DEBUG)


class Tracker(object):
    def __init__(self, dht, target):
        self.dht = dht
        self.target = target
        self.log = logging.getLogger("dht.trk.%s" % self.target.encode("hex"))
        self.dht.engine.add_interval(5, self.update_peers)
        self.log.info("Tracking %s", self.target.encode("hex"))

    def update_peers(self):
        self.dht.recurse(self.target, dht.get_peers, result_key="token").callback = self.do_announce

    def do_announce(self, txn):
        txn = txn.result
        self.dht.announce_peer(txn.addr, self.target, txn.result["token"])

        if self.target[:8] == txn.result["id"][:8]:
            self.log.info("Banning %s:%d", txn.addr[0], txn.addr[1])
            self.dht.rt.bad_node(Node(txn.addr, txn.result["id"]))
            return

        if "values" in txn.result:
            peers = map(decode_addr, txn.result["values"])
            self.log.info("Found peers: %r", peers)

class DHTServer(KRPC):
    def __init__(self, *args, **kwargs):
        KRPC.__init__(self, *args, **kwargs)
        self.supported_methods = ["ping", "find_node", "get_peers", "announce_peer"]
        self.id = random(20)
        self.log = logging.getLogger("dht.dht.%s" % self.id.encode("hex"))
        self.announce_key = random(32)
        self.rt = RoutingTable(self)
        self.infohashtable = InfoHashtable(self)

        self.engine.add_interval(10, self.print_status)
        self.engine.add_interval(5, self.reconnect)

    def print_status(self):
        self.log.info("="*40)
        self.log.info("Our contact address: %r", self.ip_vote.keys())
        self.log.info("Number of stale transactions: %d", len(self.transactions))
        self.log.info("Number of nodes in routing table: %d", self.rt.size)
        self.log.info("Number of info_hash: %d", len(self.infohashtable.table))
        self.log.info("="*40)

    def make_announce_token(self, node, info_hash):
        toktime = int(time.time())
        toktime -= toktime % 100
        return sha1(self.announce_key + str(node) + info_hash + str(toktime))[:8]

    def verify_announce_token(self, node, info_hash, token):
        return self.make_announce_token(node, info_hash) == token

    def handle_request(self, data, addr):
        if addr in self.rt.bad: return
        if addr[0] in self.ip_vote.keys(): return
        self.rt.seen_addr(addr)

        args = data["a"]
        met = data["q"]
        token = data["t"]
        if "id" in args:
            if args["id"] == self.id:
                self.rt.bad_addr(addr)
                return
            self.rt.insert_node(Node(addr, args["id"]))

        #print "%s - %s(%r)" % (token[:2].encode("hex"), met, args)
        KRPC.handle_request(self, data, addr)

    def request_ping(self, args, addr):
        return {"id": self.id}

    def request_find_node(self, args, addr):
        nodes = self.rt.find_close_nodes(args["target"])
        return {"id": self.id, "nodes": encode_nodes(nodes)}

    def request_get_peers(self, args, addr):
        node = Node(addr, args["id"])
        info_hash = args["info_hash"]
        token = self.make_announce_token(node, info_hash)
        peers = self.infohashtable.get_peers(info_hash)

        if peers:
            peers = [encode_addr(peer) for peer in peers]
            return {"id": self.id, "values": peers, "token": token}
        else:
            nodes = self.rt.find_close_nodes(info_hash)
            return {"id": self.id, "nodes": encode_nodes(nodes), "token": token}


    def request_announce_peer(self, args, addr):
        node = Node(addr, args["id"])

        if self.verify_announce_token(node, args["info_hash"], args["token"]):
            self.infohashtable.announce(args["info_hash"], addr)

        return {"id": self.id}

    def get_peers(self, addr, info_hash):
        return self.make_request(addr, "get_peers",
                id = self.id, info_hash = info_hash
            )

    def announce_peer(self, addr, info_hash, token):
        return self.make_request(addr, "announce_peer",
                id = self.id,
                implied_port = 1,
                info_hash = info_hash,
                port = 0,
                token = token,
            )

    def ping(self, addr):
        return self.make_request(addr, "ping",
                id = self.id
            )

    def find_node(self, addr, target):
        return self.make_request(addr, "find_node",
                id = self.id, target = target
            )

    def sample_infohashes(self, addr, target):
        return self.make_request(addr, "sample_infohashes",
                id = self.id, target = target
            )

    def send_near(self, target, func, avoid=[], callback=None):
        nodes = self.rt.find_close_nodes(target)
        for node in nodes:
            if node.contact in avoid: continue
            func(node.contact, target).callback = callback
        return [node.contact for node in nodes]

    def recurse(self, target, func, result_key=None, attempts=5):
        txn = Transaction()

        visited = set()

        def callback(attempt, cb_txn):
            if "nodes" in cb_txn.result:
                nodes = decode_nodes(cb_txn.result["nodes"])
                self.rt.insert_nodes(nodes)

            if result_key and result_key in cb_txn.result:
                txn.set_result(cb_txn)

            if attempt > attempts: return

            addrs = self.send_near(target, func, visited, callback=lambda cb_txn: callback(attempt+1, cb_txn))
            visited.update(addrs)

        addrs = self.send_near(target, func, visited, callback=lambda cb_txn: callback(0, cb_txn))
        visited.update(addrs)

        return txn

    def reconnect(self):
        self.recurse(self.id, self.find_node)
        self.recurse(random(20), self.find_node)

if __name__ == "__main__":
    eng = engine.Engine()
    dht = DHTServer(eng, bind=("0.0.0.0", 0))
    trck = Tracker(dht, "ee8f96a2777bd46997e71c3acc29ad4ac07101df".decode("hex"))

    eng.start()
