import logging

from angr import SimProcedure
from pise import sym_execution, server, hooks

class Gh0stSendHook(hooks.Hook):

    def get_return_value(self, buff, length, hooker):
        return 0

    def set_hook(self, p):
        p.hook_symbol('send_message', hooks.SendHook(self))

    def extract_arguments(self, hooker):
        length = hooker.state.regs.rsi
        buffer = hooker.state.regs.rdi
        return buffer, length


class Gh0stRecvHook(hooks.Hook):

    def get_return_value(self, buff, length, hooker):
        pass

    def set_hook(self, p):
        p.hook_symbol('get_message', hooks.RecvHook(self))

    def extract_arguments(self, hooker):
        length = hooker.state.regs.rsi
        buffer = hooker.state.regs.rdi
        return buffer, length


class HasMsgSimProc(SimProcedure):
    def run(self, *args, **kwargs):
        retval = self.state.solver.BVS("retval", 32)
        self.state.add_constraints(self.state.solver.Or(retval == 0, retval == 1))
        self.state.regs.eax = retval


class HasMsgHook(hooks.Hook):
    def get_return_value(self, buff, length, hooker=None):
        pass

    def set_hook(self, p):
        p.hook_symbol('has_message', HasMsgSimProc())

    def extract_arguments(self, hooker):
        pass


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('examples/ghost/gh0st_like', [Gh0stSendHook(), Gh0stRecvHook(), HasMsgHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
