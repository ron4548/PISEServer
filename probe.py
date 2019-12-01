import copy

import angr
from angr import SimProcedure

from inference_server import MessageTypeSymbol

NUM_SOLUTIONS = 10


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


class ProbeStatePlugin(angr.SimStatePlugin):

    def __init__(self, prefix, alphabet):
        super(ProbeStatePlugin, self).__init__()
        self.prefix = prefix
        self.alphabet = alphabet
        self.position = 0
        self.probing_pending = False
        self.done_probing = False
        self.probing_results = []
        self.probing_result_type = None
        self.probing_symbolic_var = None
        self.probed_symbol = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return copy.deepcopy(self)

    def is_done_prefix(self):
        return self.position == len(self.prefix)

    def handle_send(self, fd, buff_addr, buff_length):
        if self.done_probing:
            return
        if self.probing_pending:
            self.collect_pending_probe()
            return
        if self.is_done_prefix():
            constraint = True
            for symbol in self.alphabet:
                if symbol.type == 'RECEIVE' or len(symbol.predicate) == 0:
                    continue
                symbol_constraint = True
                for (k, v) in symbol.predicate.items():
                    offset = int(k)
                    value = int(v)
                    if offset >= buff_length:
                        continue
                    temp = self.state.mem[buff_addr].byte.array(buff_length).resolved[offset] == value
                    symbol_constraint = self.state.solver.And(symbol_constraint, temp)
                constraint = self.state.solver.And(constraint, self.state.solver.Not(symbol_constraint))
            self.state.solver.add(constraint)

            self.probing_symbolic_var = self.state.mem[buff_addr].string.resolved
            results = self.state.solver.eval_upto(self.probing_symbolic_var, NUM_SOLUTIONS, cast_to=bytes)
            size_bytes = len(results[0])
            # print("Probed SEND")
            # print([hex(b) for b in self.state.history.bbl_addrs])
            # results.append(self.state.solver.min(sym_var).to_bytes(size_bytes, byteorder='big'))
            # results.append(self.state.solver.max(sym_var).to_bytes(size_bytes, byteorder='big'))
            self.probing_results = results
            self.probing_result_type = 'SEND'
            self.done_probing = True
            self.probed_symbol = self.process_new_symbol()
            return

        if self.prefix[self.position].type == 'SEND':
            predicate = self.prefix[self.position].predicate
            for (k, v) in predicate.items():
                offset = int(k)
                value = int(v)
                if offset < buff_length:
                    self.state.solver.add(
                        self.state.mem[buff_addr].byte.array(buff_length).resolved[offset] == value)

            self.position = self.position + 1
        else:
            self.state.solver.add(False)

    def handle_recv(self, fd, buff_addr, buff_length):
        if self.done_probing:
            return
        if self.probing_pending:
            self.collect_pending_probe()
            return
        if self.is_done_prefix():
            sym_var = self.state.solver.BVS("x", buff_length)
            self.state.memory.store(buff_addr, sym_var)
            constraint = True
            for symbol in self.alphabet:
                if symbol.type == 'SEND' or len(symbol.predicate) == 0:
                    continue
                symbol_constraint = True
                for (k, v) in symbol.predicate.items():
                    offset = int(k)
                    value = int(v)
                    temp = sym_var.get_byte(offset) == value
                    symbol_constraint = self.state.solver.And(symbol_constraint, temp)
                constraint = self.state.solver.And(constraint, self.state.solver.Not(symbol_constraint))
            self.state.solver.add(constraint)
            self.probing_pending = True
            # print('Probed RECEIVE - pending...')
            # print(self.state.history.bbl_addrs)

            self.probing_symbolic_var = sym_var
            return

        if self.prefix[self.position].type == 'RECEIVE':
            sym_var = self.state.solver.BVS("x", buff_length)
            self.state.memory.store(buff_addr, sym_var)
            predicate = self.prefix[self.position].predicate
            for (k, v) in predicate.items():
                offset = int(k)
                value = int(v)
                self.state.solver.add(sym_var.get_byte(offset) == value)

            self.position = self.position + 1
        else:
            self.state.solver.add(False)

    def collect_pending_probe(self):
        results = self.state.solver.eval_upto(self.probing_symbolic_var, NUM_SOLUTIONS, cast_to=bytes)
        size_bytes = len(results[0])
        # results.append(self.state.solver.min(self.probing_symbolic_var).to_bytes(size_bytes, byteorder='big'))
        # results.append(self.state.solver.max(self.probing_symbolic_var).to_bytes(size_bytes, byteorder='big'))
        # print(results)
        # print([hex(b) for b in self.state.history.bbl_addrs])
        # sym_var_name, = sym_var.variables
        # rel = [constraint for constraint in self.state.solver.constraints if sym_var_name in constraint.variables]
        # print(rel)
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
                self.probing_results += [more_results]
            except Exception as e:
                print(e)
            temp = extract_predicate(self.probing_results)

            if len(temp) == len(predicate):
                break
            print('Refined symbol predicate from {} to {}'.format(len(predicate), len(temp)))
            predicate = temp

        name = extract_name(predicate)
        return MessageTypeSymbol(self.probing_result_type, name, predicate)


class ProbeHook(SimProcedure):
    def run(self, smtp, buffer, size, mode=None):
        # print('Hook on ' + str(fd))
        if mode == 'send':

            length = self.state.solver.eval(size)
            buff_addr = self.state.solver.eval(buffer)

            # self.inline_call(angr.SIM_PROCEDURES['posix']['send'], fd, buffer, size, 0)
            self.state.probe.handle_send(0, buff_addr, length)

            return 0
        else:

            length = self.state.solver.eval(size)
            buff_addr = self.state.solver.eval(buffer)
            # s = self.state.mem[self.state.solver.eval(smtp) + 0x20]
            # self.state.mem[self.state.solver.eval(smtp) + 0x20].string = self.state.solver.BVS('sym_arg', 64)

            # self.inline_call(angr.SIM_PROCEDURES['posix']['recv'], 0, buffer, size, 0)
            self.state.probe.handle_recv(0, buff_addr, length)

            return 0
            # return self.state.solver.BVS("ret", 32)
