import collections
from random import choice, sample

class InfoHashtable(object):
    def __init__(self, dht):
        self.table = collections.defaultdict(set)
#        dht.engine.add_interval(60, self.cleanup)

    def cleanup(self):
        self.table = collections.defaultdict(set)

    def announce(self, info_hash, contact):
        self.table[info_hash].add(contact)

    def get_peers(self, info_hash, N=5):
        table = self.table[info_hash]
        peers = sample(table, min(N, len(table)))
        table.difference_update(peers)
        return peers

    def seen_infohash(self, info_hash):
        return len(self.table[info_hash])


