import copy
import angr
from angr import SimProcedure


# class MonitorStatePlugin(angr.SimStatePlugin):
#
#     def __init__(self, prefix, suffix):
#         super(MonitorStatePlugin, self).__init__()
#         self.prefix = prefix
#         self.suffix = suffix
#         self.is_done = False
#         self.position = 0
#         self.outputs = []
#         self.last_output_position = 0
#         self.pending_output = False
#
#     def get_suffix_position(self):
#         if self.position < len(self.prefix):
#             return -1
#         return self.position - len(self.prefix)
#
#     @angr.SimStatePlugin.memo
#     def copy(self, memo):
#         return copy.deepcopy(self)
#
#     def handle_send(self, buff_addr, buff_length):
#         if self.is_done:
#             return
#
#         self.collect_output()
#
#         # Handle prefix symbols
#         if self.position < len(self.prefix):
#             predicate = self.prefix[self.position].predicate
#             print(predicate)
#             for (k, v) in predicate.items():
#                 offset = int(k)
#                 value = int(v)
#                 self.state.solver.add(self.state.mem[buff_addr].char.array(buff_length).resolved[offset] == chr(value))
#             self.position = self.position + 1
#         # Handle suffix symbols
#         elif self.position < len(self.prefix) + len(self.suffix):
#             predicate = self.suffix[self.position - len(self.prefix)].predicate
#             for (k, v) in predicate.items():
#                 offset = int(k)
#                 value = int(v)
#                 self.state.solver.add(self.state.mem[buff_addr].char.array(buff_length).resolved[offset] == chr(value))
#             self.position = self.position + 1
#
#     def handle_recv(self, buff_addr, length):
#         self.pending_output = True
#
#     def collect_output(self):
#         if self.pending_output:
#             socket = list(self.state.posix.sockets.values())[0]
#             concrete_output_stream = socket[0].concretize()
#             if len(concrete_output_stream) > self.last_output_position:
#                 self.outputs.append(concrete_output_stream[-1])
#                 self.last_output_position = len(concrete_output_stream)
#             else:
#                 self.outputs.append(b'error')
#
#             if self.position == len(self.prefix) + len(self.suffix):
#                 self.is_done = True
#             self.pending_output = False

class MonitorStatePlugin(angr.SimStatePlugin):

    def __init__(self, query):
        super(MonitorStatePlugin, self).__init__()
        self.input = query
        self.position = 0

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return copy.deepcopy(self)

    def is_done(self):
        return self.position == len(self.input)

    def handle_send(self, buff_addr, buff_length):
        if self.is_done():
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
        if self.is_done():
            return

        sym_var = self.state.solver.BVS("x", buff_length)
        self.state.memory.store(buff_addr, sym_var)

        if self.input[self.position].type == 'RECEIVE':
            predicate = self.input[self.position].predicate
            for (k, v) in predicate.items():
                offset = int(k)
                value = int(v)
                self.state.solver.add(sym_var.get_byte(offset) == value)

            # print("Membership query RECEIVE position: {} out of {}".format(self.position, len(self.input)))
            self.position = self.position + 1
        else:
            self.state.solver.add(False)


class MonitorHook(SimProcedure):
    def run(self, fd, buffer, size, mode=None):
        if mode == 'send':

            length = self.state.solver.eval(size)
            buff_addr = self.state.solver.eval(buffer)

            self.state.monitor.handle_send(buff_addr, length)

            return 0
        else:
            length = self.state.solver.eval(size)
            buff_addr = self.state.solver.eval(buffer)

            self.state.monitor.handle_recv(buff_addr, length)
            return 0
            # return self.state.solver.BVS("ret", 32)
