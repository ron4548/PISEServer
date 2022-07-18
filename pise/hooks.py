import logging

from angr import SimProcedure

logger = logging.getLogger(__name__)


class RecvHook(SimProcedure):
    def __init__(self, hooker, **kwargs):
        super().__init__(**kwargs)
        self.hooker = hooker

    def run(self):
        buffer_arg, length_arg = self.hooker.extract_arguments(self)
        length = self.state.solver.eval(length_arg)
        logger.debug('Receive hook with %d bytes, buff = %s' % (length, buffer_arg))
        self.state.query.handle_recv(buffer_arg, length)
        return self.hooker.get_return_value(buffer_arg, length_arg, hooker=self)


class SendHook(SimProcedure):
    def __init__(self, hooker, **kwargs):
        super().__init__(**kwargs)
        self.hooker = hooker

    def run(self):
        buffer_arg, length_arg = self.hooker.extract_arguments(self)
        length = self.state.solver.eval(length_arg)
        logger.debug('Send hook with %d bytes, buff = %s' % (length, buffer_arg))
        self.state.query.handle_send(buffer_arg, length)
        return self.hooker.get_return_value(buffer_arg, length_arg, hooker=self)


class Hook:
    def set_hook(self, p):
        raise NotImplementedError()

    def extract_arguments(self, *args):
        raise NotImplementedError()

    def get_return_value(self, buffer, length, hooker=None):
        raise NotImplementedError()


class AsyncHook:
    def resume(self):
        raise NotImplementedError()

    def emulate_recv(self):
        raise NotImplementedError()

