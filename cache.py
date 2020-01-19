import multiprocessing


class ProbingCache:
    def __init__(self):
        self.entries = dict()

    def insert(self, prefix, possible_conts):
        self.entries[tuple(prefix)] = possible_conts

    def has_contradiction(self, word):
        for prefix, conts in self.entries.items():
            if len(prefix) < len(word):
                if list(prefix) == word[:len(prefix)]:
                    if word[len(prefix)] not in conts:
                        print("%s solved by cache" % str(word))
                        return True
        return None


class SimulationCache:
    def __init__(self):
        self.root = None

    def store(self, type_ids, states):
        if len(type_ids) == 0:
            self.root = Node(states)
        else:
            if self.root is None:
                self.root = Node([])
            self.root.add_children(type_ids, states)

    def lookup(self, type_ids):
        if self.root is not None:
            length, states = self.root.lookup(type_ids)
            if states is not None:
                print("Cache lookup saved %d symbols, %d states retrieved" % (length, len(states)))
            return length, [s.copy() for s in states] if states is not None and len(states) > 0 else None
        else:
            return 0, None


class Node:
    def __init__(self, states):
        self.children = dict()
        self.states = states.copy()

    def add_children(self, type_ids, states):
        if len(type_ids) == 1:
            self.children[type_ids[0]] = Node(states)
            return

        if type_ids[0] not in self.children:
            self.children[type_ids[0]] = Node([])

        self.children[type_ids[0]].add_children(type_ids[1:], states)

    def lookup(self, type_ids):
        if len(type_ids) == 0 or type_ids[0] not in self.children:
            return 0, self.states if len(self.states) > 0 else None

        recursive_res = self.children[type_ids[0]].lookup(type_ids[1:])

        return recursive_res[0]+1, recursive_res[1] if recursive_res[1] is not None else self.states


if __name__ == '__main__':
    cache = SimulationCache()

    cache.store([2, 2], ['s1'])
    cache.store([1, 2], ['s2'])
    cache.store([1, 2, 3], ['s3', 's4'])

    print(cache.lookup([1, 2, 3, 4, 5]))
