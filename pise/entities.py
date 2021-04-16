class MessageTypeSymbol:
    id = 0

    def __init__(self, type, name, predicate, symbol_id=None):
        self.predicate = predicate
        self.name = name
        self.type = type.upper()
        if symbol_id is None:
            self.id = MessageTypeSymbol.id
            MessageTypeSymbol.id += 1
        else:
            self.id = symbol_id

    def apply_predicate(self, memory):
        pass

    def __str__(self):
        return '[{}]: {}'.format(self.type, self.name)

    def __repr__(self):
        return '[%s]: %s (ID %d)' % ('⇗' if self.type == 'SEND' else '⇘', self.name, self.id)

    def __eq__(self, other):
        return self.predicate == other.predicate and self.type == other.type

    def __hash__(self) -> int:
        return hash(frozenset(self.predicate.items()))

    def is_any(self):
        return len(self.predicate) == 0

    @staticmethod
    def from_json(symbol_json):
        return MessageTypeSymbol(symbol_json['type'], symbol_json['name'], symbol_json['predicate'], symbol_json['id'])
