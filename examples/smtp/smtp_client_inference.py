import logging
import angr
from angr import SimProcedure

from pise import sym_execution, server, hooks

class SmtpSendHook(hooks.SendReceiveCallSite):

    def get_return_value(self, buff, length, call_context):
        return 0

    def set_hook(self, p):
        p.hook_symbol('smtp_write', hooks.SendHook(self))

    def extract_arguments(self, call_context):
        length = call_context.state.regs.rdx
        buffer = call_context.state.regs.rsi
        return buffer, length


class SmtpRecvHook(hooks.SendReceiveCallSite):

    def get_return_value(self, buff, length, call_context):
        call_context.state.mem[call_context.state.regs.rdi + 0x20].uint64_t = 0x13371337
        strlen = call_context.inline_call(angr.SIM_PROCEDURES['libc']['strlen'], 0x13371337)
        call_context.state.mem[call_context.state.regs.rdi + 0x28].uint64_t = strlen.ret_expr
        for i in range(3):
            call_context.state.solver.add(call_context.state.mem[0x13371337 + i].char.resolved >= 0x30)
            call_context.state.solver.add(call_context.state.mem[0x13371337 + i].char.resolved <= 0x39)
        call_context.state.solver.add(call_context.state.mem[0x13371337 + 0x3].char.resolved == ord(' '))
        return 0

    def set_hook(self, p):
        p.hook_symbol('smtp_getline', hooks.RecvHook(self))

    def extract_arguments(self, call_context):
        length = call_context.state.solver.BVV(0x8, 64)
        buffer = call_context.state.solver.BVV(0x13371337, 64)
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('examples/smtp/smtp_client', [SmtpSendHook(), SmtpRecvHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
