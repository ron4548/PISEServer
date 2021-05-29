import logging
import os
import socket
from itertools import starmap

from pise.connection import Connection
from pise.entities import MessageTypeSymbol, MembershipQuery, MembershipQueryResult
from pise.stats import Statistics

logger = logging.getLogger(__name__)


class Server:
    def __init__(self, query_runner, port=8080):
        self.port = port
        self.pool = None
        self.sock = None
        self.query_runner = query_runner
        self.stats = None

    def handle_membership(self, query: MembershipQuery):
        inputs = query.get_inputs()

        logger.info("Running membership query on PID #{}".format(os.getpid()))
        logger.debug("Query inputs: %s" % inputs)
        answer, probe_result, ms_time, pre_probe_time, probe_time = self.query_runner.membership_step_by_step(inputs)

        self.stats.add_membership_count(1)
        self.stats.add_membership_time(ms_time)
        self.stats.add_pre_probe_time(pre_probe_time)
        self.stats.add_probe_time(probe_time)

        logger.debug(str(inputs) + " //// " + str(answer))
        query.set_result(MembershipQueryResult(answer, probe_result))
        return {
                   'membership_time': ms_time,
                   'pre_probe_time': pre_probe_time if pre_probe_time is not None else 0,
                   'probe_time': probe_time if probe_time is not None else 0,
                   'answer': answer,
                   'probe_result': probe_result
               }

    def handle_membership_batch(self, query_json):
        queries = [MembershipQuery.from_json(query) for query in query_json['queries']]
        logger.info("Got batch of {} queries".format(len(queries)))
        for query in queries:
            self.handle_membership(query)
        return [query.get_result().as_dict() for query in queries]

    def handle_connection(self, client):
        MessageTypeSymbol.id = 0
        self.stats = Statistics()
        try:
            while True:
                logger.info("Waiting for client to send queries...")
                msg = client.recv_msg()
                if msg is None:
                    break

                assert msg['type'] == 'membership_batch'
                result = self.handle_membership_batch(msg)
                client.send_msg({'result': result})

        except ConnectionError:
            logger.error('Connection error')
        finally:
            client.close()

        self.stats.print()
        self.stats = None
        logger.info("Connection done.")

    def listen(self):
        self.sock = socket.socket()
        self.sock.bind(('0.0.0.0', self.port))
        self.sock.listen()
        try:
            # while True:
            logger.info('Server is listening...')
            client_sock, addr = self.sock.accept()
            logger.info('Client connected from ' + str(addr))
            client = Connection(client_sock)
            self.handle_connection(client)
        except KeyboardInterrupt:
            logger.info('Server is stopping...')
            pass
        self.sock.close()
