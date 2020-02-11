import copy
import logging

import angr
from angr import SimProcedure, SimUnsatError

from message_type_symbol import MessageTypeSymbol

NUM_SOLUTIONS = 10
l = logging.getLogger('inference_server')


def match_byte(probing_results, i):
    ref = probing_results[0][i]
    return all(map(lambda m: m[i] == ref, probing_results))


def extract_predicate(results):
    predicate = dict()
    for i in range(len(results[0])):
        if match_byte(results, i):
            predicate[str(i)] = results[0][i]
    return predicate


def extract_name(predicate):
    if len(predicate) == 0:
        return 'ANY'
    name = ''
    for i in sorted(predicate, key=int):
        if chr(predicate[i]).isprintable():
            name += chr(predicate[i])

    if name == '':
        return 'UNKNOWN'

    return name


class MonitorStatePlugin(angr.SimStatePlugin):

    def __init__(self, query, initial_position=0):
        super(MonitorStatePlugin, self).__init__()
        self.input = query
        self.position = initial_position
        self.probing_pending = False
        self.done_probing = False
        self.probing_results = []
        self.probing_result_type = None
        self.probing_symbolic_var = None
        self.probed_symbol = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return copy.deepcopy(self)

    def is_done_membership(self):
        return self.position == len(self.input)

    def handle_send(self, buff_addr, buff_length):
        if self.done_probing:
            return

        if self.probing_pending:
            self.collect_pending_probe()
            return

        if self.is_done_membership():
            self.probing_symbolic_var = self.state.memory.load(buff_addr, buff_length)
            results = self.state.solver.eval_upto(self.probing_symbolic_var, NUM_SOLUTIONS, cast_to=bytes)
            self.probing_results = results
            self.probing_result_type = 'SEND'
            self.done_probing = True
            self.probed_symbol = self.process_new_symbol()
            return

        if self.input[self.position].type == 'SEND':
            predicate = self.input[self.position].predicate
            for (k, v) in predicate.items():
                offset = int(k)
                value = int(v)

                if offset >= buff_length:
                    continue

                self.state.solver.add(self.state.mem[buff_addr].byte.array(buff_length).resolved[offset] == value)

            # print("Membership query SEND position: {} out of {}".format(self.position, len(self.input)))
            self.position = self.position + 1
        else:
            self.state.solver.add(False)

    def handle_recv(self, buff_addr, buff_length):
        if self.done_probing:
            return

        if self.probing_pending:
            self.collect_pending_probe()
            return

        if self.is_done_membership():
            # Store symbolic value for the recieved message
            sym_var = self.state.solver.BVS("x", buff_length * 8)
            self.state.memory.store(buff_addr, sym_var)

            # Wait for constraints to accumulate
            self.probing_pending = True
            self.probing_symbolic_var = sym_var
            return

        if self.input[self.position].type == 'RECEIVE':
            sym_var = self.state.solver.BVS("x", buff_length * 8)
            self.state.memory.store(buff_addr, sym_var)
            predicate = self.input[self.position].predicate
            for (k, v) in predicate.items():
                offset = int(k)
                value = int(v)
                self.state.solver.add(sym_var.get_byte(offset) == value)

            # print("Membership query RECEIVE position: {} out of {}".format(self.position, len(self.input)))
            self.position = self.position + 1
        else:
            self.state.solver.add(False)

    def collect_pending_probe(self):
        l.debug('Collecting pending probe')
        results = self.state.solver.eval_upto(self.probing_symbolic_var, NUM_SOLUTIONS, cast_to=bytes)
        self.done_probing = True
        self.probing_pending = False
        self.probing_results = results
        self.probing_result_type = 'RECEIVE'
        self.probed_symbol = self.process_new_symbol()
        return

    def process_new_symbol(self):
        predicate = extract_predicate(self.probing_results)
        while True:
            constraint = False

            for (k, v) in predicate.items():
                offset = int(k)
                value = int(v)
                t = self.probing_symbolic_var.get_byte(offset) != value
                constraint = self.state.solver.Or(constraint, t)

            try:
                more_results = self.state.solver.eval(self.probing_symbolic_var,
                                                      cast_to=bytes, extra_constraints=[constraint])
                l.debug(more_results)
                self.probing_results += [more_results]
            except SimUnsatError as e:
                l.debug('Done refining predicate')
            temp = extract_predicate(self.probing_results)

            if len(temp) == len(predicate):
                break
            l.info('Refined symbol predicate from {} to {}'.format(len(predicate), len(temp)))
            predicate = temp

        name = extract_name(predicate)
        new_symbol = MessageTypeSymbol(self.probing_result_type, name, predicate)
        l.debug('New symbol discovered: %s' % new_symbol.__str__())
        l.debug('Predicate: %s' % new_symbol.predicate)
        return new_symbol


class RecvHook(SimProcedure):
    def __init__(self, hooker, **kwargs):
        super().__init__(**kwargs)
        self.hooker = hooker

    def run(self):
        buffer_arg, length_arg = self.hooker.extract_arguments(self.state)
        length = self.state.solver.eval(length_arg)
        l.debug('Receive hook with %d bytes, buff = %s' % (length, buffer_arg))
        self.state.monitor.handle_recv(buffer_arg, length)
        return self.hooker.get_return_value(buffer_arg, length_arg)


class SendHook(SimProcedure):
    def __init__(self, hooker, **kwargs):
        super().__init__(**kwargs)
        self.hooker = hooker

    def run(self):
        buffer_arg, length_arg = self.hooker.extract_arguments(self.state)
        length = self.state.solver.eval(length_arg)
        l.debug('Send hook with %d bytes, buff = %s' % (length, buffer_arg))
        self.state.monitor.handle_send(buffer_arg, length)
        return self.hooker.get_return_value(buffer_arg, length_arg)


class Hooker:
    def set_hook(self, p):
        raise NotImplementedError()

    def extract_arguments(self, *args):
        raise  NotImplementedError()

    def get_return_value(self, buffer, length):
        raise NotImplementedError()