import multiprocessing
import os
import socket
import json
from json import JSONEncoder
from multiprocessing.pool import Pool

import monitor


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
        return '[%s]: %s (%d)' % (self.type, self.name, self.id)

    def as_json(self):
        return {
            'name': self.name,
            'type': self.type,
            'predicate': self.predicate,
            'id': self.id
        }

    @staticmethod
    def from_json(symbol_json):
        return MessageTypeSymbol(symbol_json['type'], symbol_json['name'], symbol_json['predicate'], symbol_json['id'])


def handle_membership(m, query_json):
    inputs = []
    for symbol_json in query_json['input']:
        inputs.append(MessageTypeSymbol.from_json(symbol_json))

    return m.run_membership_query(inputs)


def parse_array_of_symbols(input_json_array):
    inputs = []
    for symbol_json in input_json_array:
        inputs.append(MessageTypeSymbol.from_json(symbol_json))

    return inputs


def handle_membership_concurrent(m, query_json, alphabet):
    inputs = parse_array_of_symbols(query_json['input'])

    print("Running membership query on PID #{}".format(os.getpid()))
    print(inputs)
    answer, probe_result, ms_time, pre_probe_time, probe_time = m.run_membership_query(inputs, alphabet)

    if probe_result is None:
        symbols = []
    else:
        symbols = list(map(lambda o: o.as_json(), probe_result))
    symbols_json = json.dumps(symbols)

    return {
               'membership_time': ms_time,
               'pre_probe_time': pre_probe_time if pre_probe_time is not None else 0,
               'probe_time': probe_time if probe_time is not None else 0,
               'answer': answer,
               'probe_result': symbols_json
           }, ms_time, pre_probe_time, probe_time


def handle_probe(m, query_json):
    prefix = parse_array_of_symbols(query_json['prefix'])
    alphabet = parse_array_of_symbols(query_json['alphabet'])
    return m.run_probe_query(prefix, alphabet)


def handle_membership_batch(m, p, query_json):
    monitors = [m for i in range(len(query_json['queries']))]
    alphabet = parse_array_of_symbols(query_json['alphabet'])
    alphabets = [alphabet for i in range(len(monitors))]
    results = p.starmap(handle_membership_concurrent, zip(monitors, query_json['queries'], alphabets))
    results = list(results)
    ms_time = sum([ms_time for _, ms_time, _, _ in results])
    pre_probe_time = sum([pre_probe_time for _, _, pre_probe_time, _ in results if pre_probe_time is not None])
    probe_time = sum([probe_time for _, _, _, probe_time in results if probe_time is not None])

    answers = [ans for ans, _, _, _ in results]
    results = json.dumps(answers)
    return results, ms_time, pre_probe_time, probe_time


def handle_connection(conn):
    p = Pool()
    m = monitor.QueryRunner(file='smtp/smtp-client')
    MessageTypeSymbol.id = 0
    count_ms = 0
    count_probe = 0
    ms_time = 0
    pre_probe_time = 0
    probe_time = 0
    while True:
        data = ''
        print("Waiting for client to send queries...")
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
        elif query_json['type'] == 'membership_batch':
            count_ms += len(query_json['queries'])
            print("Got batch of {} queries".format(len(query_json['queries'])))
            result = handle_membership_batch(m, p, query_json)
            ms_time += result[1]
            pre_probe_time += result[2]
            probe_time += result[3]
            result = result[0] + '\n'
            conn.send(result.encode('utf-8'))
    p.close()
    print("Connection done.")
    print("Membership queries processed: {}".format(count_ms))
    print("Memberships took: %d" % ms_time)
    print("Pre-probings took: %d" % pre_probe_time)
    print("Probing took: %d" % probe_time)


def start_server():
    s = socket.socket()
    s.bind(('0.0.0.0', 8080))
    s.listen()
    while True:
        print('Waiting for client...')
        conn, addr = s.accept()
        print('Client connected from ' + str(addr))
        try:
            handle_connection(conn)
        except ConnectionError:
            conn.close()
            continue

    s.close()


if __name__ == '__main__':
    start_server()
