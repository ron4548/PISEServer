import logging
import multiprocessing
import os
import socket
import json
from itertools import starmap
from json import JSONEncoder
from multiprocessing.pool import Pool

import monitor
from message_type_symbol import MessageTypeSymbol

l = logging.getLogger('inference_server')


def parse_array_of_symbols(input_json_array):
    inputs = []
    for symbol_json in input_json_array:
        inputs.append(MessageTypeSymbol.from_json(symbol_json))

    return inputs


class InferenceServer:
    def __init__(self, binary, hookers, port=8080):
        self.port = port
        self.pool = None
        self.sock = None
        self.query_runner = monitor.QueryRunner(binary, hookers)

    def handle_membership_concurrent(self, query_json):
        inputs = parse_array_of_symbols(query_json['input'])

        l.info("Running membership query on PID #{}".format(os.getpid()))
        l.debug("Query inputs: %s" % inputs)
        answer, probe_result, ms_time, pre_probe_time, probe_time = self.query_runner.membership_step_by_step(inputs)

        if probe_result is None:
            symbols = []
        else:
            symbols = list(map(lambda o: o.as_json(), probe_result))
        symbols_json = json.dumps(symbols)
        l.debug(str(inputs) + " //// " + str(answer))
        return {
                   'membership_time': ms_time,
                   'pre_probe_time': pre_probe_time if pre_probe_time is not None else 0,
                   'probe_time': probe_time if probe_time is not None else 0,
                   'answer': answer,
                   'probe_result': symbols_json
               }, ms_time, pre_probe_time, probe_time

    def handle_membership_batch(self, query_json):
        zipped_list = zip(query_json['queries'])
        results = starmap(self.handle_membership_concurrent, zipped_list)
        results = list(results)
        ms_time = sum([ms_time for _, ms_time, _, _ in results])
        pre_probe_time = sum([pre_probe_time for _, _, pre_probe_time, _ in results if pre_probe_time is not None])
        probe_time = sum([probe_time for _, _, _, probe_time in results if probe_time is not None])

        answers = [ans for ans, _, _, _ in results]
        results = json.dumps(answers)
        return results, ms_time, pre_probe_time, probe_time

    def handle_connection(self, conn):
        self.pool = Pool(processes=1)
        MessageTypeSymbol.id = 0
        count_ms = 0
        ms_time = 0
        pre_probe_time = 0
        probe_time = 0
        while True:
            data = ''
            l.info("Waiting for client to send queries...")
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

            if query_json['type'] == 'membership_batch':
                count_ms += len(query_json['queries'])
                l.info("Got batch of {} queries".format(len(query_json['queries'])))
                result = self.handle_membership_batch(query_json)
                ms_time += result[1]
                pre_probe_time += result[2]
                probe_time += result[3]
                result = result[0] + '\n'
                conn.send(result.encode('utf-8'))
            else:
                l.error('Unknown packet type: %s' % query_json['type'])
        self.pool.close()
        l.info("Connection done.")
        l.info("Membership queries processed: {}".format(count_ms))
        l.info("Memberships took: %d" % ms_time)
        l.info("Pre-probings took: %d" % pre_probe_time)
        l.info("Probing took: %d" % probe_time)

    def start(self):
        s = socket.socket()
        s.bind(('0.0.0.0', self.port))
        s.listen()
        self.sock = s
        while True:
            l.info('Waiting for client...')
            conn, addr = s.accept()
            l.info('Client connected from ' + str(addr))
            try:
                self.handle_connection(conn)
            except ConnectionError:
                conn.close()
                continue

        s.close()
        self.sock = None
