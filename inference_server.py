import socket
import json
from json import JSONEncoder

import monitor


class MessageTypeSymbol:
    def __init__(self, type, name, predicate):
        self.predicate = predicate
        self.name = name
        self.type = type.upper()

    def apply_predicate(self, memory):
        pass

    def __str__(self):
        return '[{}]: {}'.format(self.type, self.name)

    def as_json(self):
        return {
            'name': self.name,
            'type': self.type,
            'predicate': self.predicate
        }


def handle_membership(m, query_json):
    inputs = []
    for symbol_json in query_json['input']:
        inputs.append(MessageTypeSymbol(symbol_json['type'], symbol_json['name'], symbol_json['predicate']))

    return m.run_membership_query(inputs)


def handle_probe(m, query_json):
    prefix = []
    for symbol_json in query_json['prefix']:
        prefix.append(MessageTypeSymbol(symbol_json['type'], symbol_json['name'], symbol_json['predicate']))

    alphabet = []
    for symbol_json in query_json['alphabet']:
        alphabet.append(MessageTypeSymbol(symbol_json['type'], symbol_json['name'], symbol_json['predicate']))
    return m.run_probe_query(prefix, alphabet)


def handle_connection(conn):
    m = monitor.QueryRunner()
    count_ms = 0
    count_probe = 0
    while True:
        data = ''
        r = conn.recv(1024)
        if r.decode('utf-8').strip() == 'BYE':
            conn.close()
            break
        while True:
            data += r.decode('utf-8').strip()
            if data.endswith('DONE'):
                break
            r = conn.recv(1024)

        data = data[:len(data) - 4]
        query_json = json.loads(data)

        if query_json['type'] == 'membership':
            count_ms += 1
            result = handle_membership(m, query_json)
            conn.send(result + b'\n')
        elif query_json['type'] == 'probe':
            count_probe += 1
            result = list(map(lambda o: o.as_json(), handle_probe(m, query_json)))
            result_json = json.dumps(result)
            result_json = result_json + '\n'
            conn.send(result_json.encode('utf-8'))
    print("Connection done.")
    print("Membership queries processed: {}".format(count_ms))
    print("Probing queries processed: {}".format(count_probe))

def start_server():
    s = socket.socket()
    s.bind(('0.0.0.0', 8080))
    s.listen()
    while True:
        print('Waiting for client...')
        conn, addr = s.accept()
        print('Client connected from ' + str(addr))
        handle_connection(conn)

    s.close()


if __name__ == '__main__':
    start_server()
