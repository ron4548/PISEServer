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


class MonitorStatePlugin(angr.SimStatePlugin):

    def __init__(self, query, alphabet):
        super(MonitorStatePlugin, self).__init__()
        self.input = query
        self.position = 0
        self.alphabet = alphabet
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
            # Prevent discovery of known message types
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
            # self.state.solver.add(constraint)

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

            # Prevent discovery of known message types
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
            # self.state.solver.add(constraint)

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


class MonitorHook(SimProcedure):
    def run(self, fd, buffer, size, mode=None):
        if mode == 'send':

            length = self.state.solver.eval(size)
            # buff_addr = self.state.solver.eval(buffer)

            self.state.monitor.handle_send(buffer, length)

            return 0
        else:
            length = self.state.solver.eval(size)
            # buff_addr = self.state.solver.eval(buffer)

            self.state.monitor.handle_recv(buffer, length)
            return 0
            # return self.state.solver.BVS("ret", 32)
