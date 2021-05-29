import logging

import angr

import sym_ex_helpers
from pise import InferenceServer


class SendHooker(sym_ex_helpers.Hooker):

    def get_return_value(self, buff, length):
        return 0

    def set_hook(self, p):
        p.hook_symbol('smtp_write', sym_ex_helpers.SendHook(self))

    def extract_arguments(self, state):
        length = state.regs.rdx
        buffer = state.regs.rsi
        return buffer, length


class RecvHooker(sym_ex_helpers.Hooker):

    def get_return_value(self, buff, length):
        return 0

    def set_hook(self, p):
        p.hook_symbol('smtp_read_aux', sym_ex_helpers.RecvHook(self))
        p.hook_symbol('strtoul', angr.SIM_PROCEDURES['libc']['strtol']())

    def extract_arguments(self, state):
        length = state.regs.edx
        buffer = state.regs.rsi
        return buffer, length


if __name__ == "__main__":
    logging.getLogger('pise').setLevel(logging.DEBUG)
    inference_server = InferenceServer('smtp/smtp-client', [SendHooker(), RecvHooker()])

    inference_server.start()
