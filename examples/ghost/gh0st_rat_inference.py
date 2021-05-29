import logging

from pise import sym_execution, server, hooks


class Gh0stSendHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('send', hooks.SendHook(self))

    def extract_arguments(self, state):
        length = state.regs.edx
        buffer = state.regs.rsi
        return buffer, length


class Gh0stRecvHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('recv', hooks.RecvHook(self))

    def extract_arguments(self, state):
        length = state.regs.edx
        buffer = state.regs.rsi
        return buffer, length


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('gh0st.exe', [Gh0stSendHook(), Gh0stRecvHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
