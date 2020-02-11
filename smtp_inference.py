import logging

import angr

import membership
import monitor
from inference_server import InferenceServer


class SendHooker(membership.Hooker):

    def get_return_value(self, buff, length):
        return 0

    def set_hook(self, p):
        p.hook_symbol('smtp_write', membership.SendHook(self))

    def extract_arguments(self, state):
        length = state.regs.rdx
        buffer = state.regs.rsi
        return buffer, length


class RecvHooker(membership.Hooker):

    def get_return_value(self, buff, length):
        return 0

    def set_hook(self, p):
        p.hook_symbol('smtp_read_aux', membership.RecvHook(self))
        p.hook_symbol('strtoul', angr.SIM_PROCEDURES['libc']['strtol']())

    def extract_arguments(self, state):
        length = state.regs.edx
        buffer = state.regs.rsi
        return buffer, length


if __name__ == "__main__":
    logging.getLogger('inference_server').setLevel(logging.DEBUG)
    inference_server = InferenceServer('smtp/smtp-client', [SendHooker(), RecvHooker()])

    inference_server.start()
