import logging
import angr
from angr import SimProcedure

from pise import sym_execution, server, hooks

class SmtpSendHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return 0

    def set_hook(self, p):
        p.hook_symbol('smtp_write', hooks.SendHook(self))

    def extract_arguments(self, hooker):
        length = hooker.state.regs.rdx
        buffer = hooker.state.regs.rsi
        return buffer, length


class SmtpRecvHook(hooks.Hook):

    def get_return_value(self, buff, length, hooker):
        hooker.state.mem[hooker.state.regs.rdi + 0x20].uint64_t = 0x13371337
        strlen = hooker.inline_call(angr.SIM_PROCEDURES['libc']['strlen'], 0x13371337)
        hooker.state.mem[hooker.state.regs.rdi + 0x28].uint64_t = strlen.ret_expr
        for i in range(3):
            hooker.state.solver.add(hooker.state.mem[0x13371337 + i].char.resolved >= 0x30)
            hooker.state.solver.add(hooker.state.mem[0x13371337 + i].char.resolved <= 0x39)
        hooker.state.solver.add(hooker.state.mem[0x13371337 + 0x3].char.resolved == ord(' '))
        return 0

    def set_hook(self, p):
        p.hook_symbol('smtp_getline', hooks.RecvHook(self))

    def extract_arguments(self, hooker):
        length = hooker.state.solver.BVV(0x8, 64)
        buffer = hooker.state.solver.BVV(0x13371337, 64)
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('smtp_client', [SmtpSendHook(), SmtpRecvHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
