import logging

import angr
from angr import SimProcedure

from pise import sym_execution, server, hooks

IOCPClient__OnServerSending = 0x406550


class Gh0stSendHook(hooks.Hook):

    def get_return_value(self, buff, length):
        return 0

    def set_hook(self, p):
        p.hook(IOCPClient__OnServerSending, hooks.SendHook(self))

    def extract_arguments(self, state):
        length = state.mem[state.regs.esp + 0xc].int
        buffer = state.mem[state.regs.esp + 0x8].int
        return buffer, length


IOCPClient__OnServerReceiving = 0x406120


class Gh0stRecvHook(hooks.Hook):

    def get_return_value(self, buff, length):
        raise NotImplementedError

    def set_hook(self, p):
        p.hook(IOCPClient__OnServerReceiving, AsyncRecvHook())

    def extract_arguments(self, state):
        raise NotImplementedError


class AsyncRecvHook(SimProcedure):
    IS_FUNCTION = True
    local_vars = ()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def run(self):
        buffer_arg = 0x1337
        length = 0x40
        self.state.query.handle_recv(buffer_arg, length)
        mgr_ptr = self.state.mem[self.state.regs.ecx + 0x20].int.concrete
        vtable_ptr = self.state.mem[mgr_ptr].int.concrete
        addr = self.state.mem[vtable_ptr + 0x4].int.concrete
        self.state.regs.ecx = mgr_ptr
        self.call(addr=addr, args=(buffer_arg, length), continue_at='cont')

    def cont(self):
        return self.state.regs.al


class CreateThreadSimProc(SimProcedure):
    IS_FUNCTION = True
    local_vars = ()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def run(self):
        addr = self.state.mem[self.regs.esp + 0xc].int.concrete
        self.state.add_successor(self.state, addr, self.state.solver.true, 'whatnot')


class CreateThreadHook(hooks.Hook):

    def set_hook(self, p):
        p.hook_symbol('CreateThread', CreateThreadSimProc())

    def extract_arguments(self, *args):
        pass

    def get_return_value(self, buffer, length):
        pass


# Entry point might need to be at StartClient @ 0x403db0
# We need to handle CreateThread calls to handle such execution paths.
# RecvHook should happen at IOCPClient::OnServerReceiving
# After receiving, the hook should resume at OnReceive virtual method, located at offset 4 in the vtable.
# address of onReceive virtual method: (*(*(ecx + 0x20)) + 4)


def main():
    logging.getLogger('pise').setLevel(logging.DEBUG)
    query_runner = sym_execution.QueryRunner('gh0st.exe', [Gh0stSendHook(), Gh0stRecvHook(), CreateThreadHook()])
    s = server.Server(query_runner)
    s.listen()


if __name__ == "__main__":
    main()
