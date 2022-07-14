import logging

from pise import sym_execution, server, hooks


class ToySendHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('send', hooks.SendHook(self))

    def extract_arguments(self, hooker):
        length = hooker.state.regs.edx
        buffer = hooker.state.regs.rsi
        return buffer, length


class ToyRecvHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('recv', hooks.RecvHook(self))

    def extract_arguments(self, hooker):
        length = hooker.state.regs.edx
        buffer = hooker.state.regs.rsi
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('examples/toy_example/toy_example', [ToySendHook(), ToyRecvHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
