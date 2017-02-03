import engine
from krpc import *
from routingtable import *
from infohashtable import *
from collections import Counter

class DHTServer(KRPC):
    supported_methods = ["ping", "find_node", "get_peers", "announce_peer"]

    def __init__(self, *args, **kwargs):
        KRPC.__init__(self, *args, **kwargs)
        self.id = random(20)
        self.announce_key = random(32)
        self.rt = RoutingTable(self)
        self.infohashtable = InfoHashtable(self)

        self.engine.add_interval(10, self.print_status)
        self.engine.add_interval(5, self.reconnect)

    def print_status(self):
        print "="*40
        print "Node id:", self.id.encode("hex")
        print "Our contact address:", self.ip_vote.keys()
        print "Number of stale transactions:", len(self.transactions)
        print "Number of buckets in routing table:", len(self.rt.buckets)
        print "Number of nodes in routing table:", self.rt.size
        print "Number of info_hash:", len(self.infohashtable.table)
        print "="*40

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

        print "%s - %s(%r)" % (token[:2].encode("hex"), met, args)
        KRPC.handle_request(self, data, addr)

    def request_ping(self, args, addr):
        id = args["id"]
        self.rt.insert_node(Node(addr, id))
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
                port = 1337,
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

    def recurse(self, target, function, result_key=None, attempts=10):
        txn = Transaction()

        visited = set()

        def callback(attempt, cb_txn):
            if "nodes" in cb_txn.result:
                nodes = decode_nodes(cb_txn.result["nodes"])
                self.rt.insert_nodes(nodes)

            if result_key and result_key in cb_txn.result:
                txn.set_result(cb_txn.result)
                return

            if attempt > attempts:
                return

            nodes = self.rt.find_close_nodes(target)
            for node in nodes:
                if node.contact in visited: continue
                visited.add(node.contact)
                function(node.contact, target).callback = lambda cb_txn: callback(attempt+1, cb_txn)

        nodes = self.rt.find_close_nodes(target)
        for node in nodes:
            function(node.contact, target).callback = lambda cb_txn: callback(0, cb_txn)

        return txn

    def reconnect(self):
        self.recurse(self.id, self.find_node)


if __name__ == "__main__":
    eng = engine.Engine()
    serv = DHTServer(eng, bind=("0.0.0.0", 1337))

    def expand_routing_table():
        for i in range(16):
            serv.recurse(random(20), serv.find_node)

#    eng.add_interval(10, expand_routing_table)
    eng.start()
