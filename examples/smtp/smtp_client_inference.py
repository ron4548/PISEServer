import logging
import angr

from pise import sym_execution, server, hooks


class SmtpSendHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('smtp_write', hooks.SendHook(self))

    def extract_arguments(self, hooker):
        length = hooker.state.regs.rdx
        buffer = hooker.state.regs.rsi
        return buffer, length


class SmtpRecvHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('smtp_read_aux', hooks.RecvHook(self))
        p.hook_symbol('strtoul', angr.SIM_PROCEDURES['libc']['strtol']())

    def extract_arguments(self, hooker):
        length = hooker.state.regs.rdx
        buffer = hooker.state.regs.rsi
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('smtp_client', [SmtpSendHook(), SmtpRecvHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
