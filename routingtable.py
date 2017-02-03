import time
import collections
from random import choice, sample
from krpc import *

CONTACT_TIMEOUT = 30*60
PREFIX_SIZE = 1

class RoutingTable(object):
    def __init__(self, dht):
        self.dht = dht
        self.buckets = collections.defaultdict(set)
        self.bad = set()
        self.seen = set()
        eng = self.dht.engine
        self.cleanup_timer = eng.add_interval(60, self.cleanup)
        self.maintain_timer = eng.add_interval(5, self.maintain)
        self.bootstrap()

    @property
    def size(self):
        return sum(len(bucket) for bucket in self.buckets.values())

    def insert_nodes(self, nodes):
        for node in nodes:
            self.insert_node(node)

    def insert_node(self, node):
        if node.contact in self.bad: return
        if node.id == self.dht.id: return
        prefix = node.id[:PREFIX_SIZE]
        self.buckets[prefix].add(node)

    def remove_node(self, node):
        prefix = node.id[:PREFIX_SIZE]
        bucket = self.buckets[prefix]
        try:
            bucket.remove(node)
        except KeyError:
            pass
    
    def seen_addr(self, addr):
        if addr not in self.seen:
            self.seen.add(addr)
            self.dht.ping(addr).callback = self.ping_reply

    def bad_addr(self, addr):
        self.bad.add(addr)

    def bad_node(self, node):
        self.remove_node(node)
        self.bad_addr(node.contact)

    def find_close_nodes(self, target, N=5):
        prefix = target[:PREFIX_SIZE]
        bucket = self.buckets[prefix]
        nodes = list(bucket)
        if not nodes: return self.sample(N)
        nodes.sort(key=lambda x: xor(target, x.id))
        return nodes[:N]

    def sample(self, N=5):
        bucket = choice(self.buckets.values())
        return sample(bucket, min(N, len(bucket)))

    def bootstrap(self):
        addr = get_bootstrap_addr()
        self.dht.ping(addr).callback = self.ping_reply

    def ping_reply(self, txn):
        node = Node(txn.addr, txn.result["id"])
        node.last_ping = int(time.time())
        self.insert_node(node)

    def maintain(self):
        for node in self.sample(10):
            self.dht.ping(node.contact).callback = self.ping_reply

    def cleanup(self):
        self.seen = set()

        for bucket in self.buckets.values():
            for node in list(bucket):
                if int(time.time()) - node.last_ping > CONTACT_TIMEOUT:
                    self.remove_node(node)

        for prefix in self.buckets.keys():
            try:
                self.buckets[prefix] = set(sample(self.buckets[prefix], 100))
            except ValueError:
                pass
