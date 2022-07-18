import logging

from angr import SimProcedure

logger = logging.getLogger(__name__)


class RecvHook(SimProcedure):
    def __init__(self, callsite_handler, **kwargs):
        super().__init__(**kwargs)
        self.callsite_handler = callsite_handler

    def run(self):
        buffer_arg, length_arg = self.callsite_handler.extract_arguments(self)
        length = self.state.solver.eval(length_arg)
        logger.debug('Receive hook with %d bytes, buff = %s' % (length, buffer_arg))
        self.state.query.handle_recv(buffer_arg, length)
        return self.callsite_handler.get_return_value(buffer_arg, length_arg, call_context=self)


class SendHook(SimProcedure):
    def __init__(self, callsite_handler, **kwargs):
        super().__init__(**kwargs)
        self.callsite_handler = callsite_handler

    def run(self):
        buffer_arg, length_arg = self.callsite_handler.extract_arguments(self)
        length = self.state.solver.eval(length_arg)
        logger.debug('Send hook with %d bytes, buff = %s' % (length, buffer_arg))
        self.state.query.handle_send(buffer_arg, length)
        return self.callsite_handler.get_return_value(buffer_arg, length_arg, call_context=self)


# This interface describes a callsite that sends/receive messages in the binary, and therefore should be hooked
class SendReceiveCallSite:
    # This function should set the hook within the symbolic execution engine
    # In our case it gets the angr project with the executable loaded
    # Return value is ignored
    def set_hook(self, angr_project):
        raise NotImplementedError()

    # This function should extract the buffer pointer and the buffer length from the program state
    # It is given the call_context as angr's SimProcedure instance, which contains under call_context.state the program state
    # Should return: (buffer, length) tuple
    def extract_arguments(self, call_context):
        raise NotImplementedError()

    # This function should return the suitable return value to simulate a successful send or receive from the callsite
    # It is given the buffer, the length and the call_context (which contains the state)
    # Should return: the return value that will be passed to the caller
    def get_return_value(self, buffer, length, call_context):
        raise NotImplementedError()


class AsyncHook:
    def resume(self):
        raise NotImplementedError()

    def emulate_recv(self):
        raise NotImplementedError()

