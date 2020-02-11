import logging

import angr

import membership
import monitor
from inference_server import InferenceServer


class SendHooker(membership.Hooker):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('send', membership.SendHook(self))

    def extract_arguments(self, state):
        length = state.regs.edx
        buffer = state.regs.rsi
        return buffer, length


class RecvHooker(membership.Hooker):

    def get_return_value(self, buff, length):
        return length

    def set_hook(self, p):
        p.hook_symbol('recv', membership.RecvHook(self))

    def extract_arguments(self, state):
        length = state.regs.edx
        buffer = state.regs.rsi
        return buffer, length


if __name__ == "__main__":
    logging.getLogger('inference_server').setLevel(logging.DEBUG)
    inference_server = InferenceServer('client', [SendHooker(), RecvHooker()])
    inference_server.start()
