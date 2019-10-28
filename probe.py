import copy

import angr
from angr import SimProcedure

NUM_SOLUTIONS = 5

class ProbeStatePlugin(angr.SimStatePlugin):

    def __init__(self, prefix, alphabet):
        super(ProbeStatePlugin, self).__init__()
        self.prefix = prefix
        self.alphabet = alphabet
        self.position = 0
        self.probing_pending = False
        self.done_probing = False
        self.probing_location = None
        self.probing_results = []
        self.probing_result_type = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return copy.deepcopy(self)

    def is_done_prefix(self):
        return self.position == len(self.prefix)

    def handle_send(self, buff_addr, buff_length):
        if self.done_probing:
            return
        if self.probing_pending:
            self.collect_pending_probe()
            return
        if self.is_done_prefix():
            constraint = True
            for symbol in self.alphabet:
                symbol_constraint = True
                for (k, v) in symbol.predicate.items():
                    offset = int(k)
                    value = int(v)
                    if offset >= buff_length:
                        continue
                    temp = self.state.mem[buff_addr].char.array(buff_length).resolved[offset] == chr(value)
                    symbol_constraint = self.state.solver.And(symbol_constraint, temp)
                constraint = self.state.solver.And(constraint, self.state.solver.Not(symbol_constraint))
            self.state.solver.add(constraint)
            sym_var = list(self.state.posix.sockets.values())[0][1].content[-1][0]
            results = self.state.solver.eval_upto(sym_var, NUM_SOLUTIONS, cast_to=bytes)
            size_bytes = len(results[0])
            # results.append(self.state.solver.min(sym_var).to_bytes(size_bytes, byteorder='big'))
            # results.append(self.state.solver.max(sym_var).to_bytes(size_bytes, byteorder='big'))
            self.probing_results = results
            self.probing_result_type = 'SEND'
            self.done_probing = True
            return

        if self.prefix[self.position].type == 'SEND':
            predicate = self.prefix[self.position].predicate
            for (k, v) in predicate.items():
                offset = int(k)
                value = int(v)
                if offset < buff_length:
                    self.state.solver.add(self.state.mem[buff_addr].char.array(buff_length).resolved[offset] == chr(value))

            self.position = self.position + 1
        else:
            self.state.solver.add(False)

    def handle_recv(self, buff_addr, buff_length):
        if self.done_probing:
            return
        if self.probing_pending:
            self.collect_pending_probe()
            return
        if self.is_done_prefix():
            constraint = True
            for symbol in self.alphabet:
                symbol_constraint = True
                for (k, v) in symbol.predicate.items():
                    offset = int(k)
                    value = int(v)
                    temp = self.state.mem[buff_addr].char.array(buff_length).resolved[offset] == chr(value)
                    symbol_constraint = self.state.solver.And(symbol_constraint, temp)
                constraint = self.state.solver.And(constraint, self.state.solver.Not(symbol_constraint))
            self.state.solver.add(constraint)
            self.probing_pending = True
            self.probing_location = self.state.mem[buff_addr]
            return

        if self.prefix[self.position].type == 'RECEIVE':
            predicate = self.prefix[self.position].predicate
            for (k, v) in predicate.items():
                offset = int(k)
                value = int(v)
                self.state.solver.add(self.state.mem[buff_addr].char.array(buff_length).resolved[offset] == chr(value))

            self.position = self.position + 1
        else:
            self.state.solver.add(False)

    def collect_pending_probe(self):
        sym_var = list(self.state.posix.sockets.values())[0][0].content[-1][0]
        results = self.state.solver.eval_upto(sym_var, NUM_SOLUTIONS, cast_to=bytes)
        size_bytes = len(results[0])
        # results.append(self.state.solver.min(sym_var).to_bytes(size_bytes, byteorder='big'))
        # results.append(self.state.solver.max(sym_var).to_bytes(size_bytes, byteorder='big'))
        print(results)
        # sym_var_name, = sym_var.variables
        # rel = [constraint for constraint in self.state.solver.constraints if sym_var_name in constraint.variables]
        # print(rel)
        self.done_probing = True
        self.probing_pending = False
        self.probing_results = results
        self.probing_result_type = 'RECEIVE'
        return


class ProbeHook(SimProcedure):
    def run(self, fd, buffer, size, mode=None):
        if mode == 'send':

            length = self.state.solver.eval(size)
            buff_addr = self.state.solver.eval(buffer)

            self.inline_call(angr.SIM_PROCEDURES['posix']['send'], fd, buffer, size, 0)
            self.state.probe.handle_send(buff_addr, length)
        else:
            length = self.state.solver.eval(size)
            buff_addr = self.state.solver.eval(buffer)

            self.inline_call(angr.SIM_PROCEDURES['posix']['read'], fd, buffer, size, 0)
            self.state.probe.handle_recv(buff_addr, length)

