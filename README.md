# PISE Server

PISE (Protocol Inference with Symbolic Execution) is a tool that leverages symbolic execution and automata learning to uncover the state machine of a protocol implemented in a given executable. It is available in two modules:

- The server (this repo): for performing the symbolic execution. Implemented in Python.
- [The client](https://github.com/ron4548/InferenceClient): responsible for automata learning. Implemented in Java.

#### Dependencies

- angr


#### Setup

In order to start working with PISE, first clone this repo:

```shell
git clone https://github.com/ron4548/InferenceServer.git
cd InferenceServer
```

We recommend working with virtual environments, as angr recommends doing so:

```shell
python -m venv ./venv
source ./venv/bin/activate
```

Now install all the required python packages:

```shell
pip install -r requirements.txt
```

And you are done.

#### Applying the method on a toy example

We demonstrate the application of the tool on a toy client we provide (`examples/toy_example/toy_example.c`). You can compile this example by execution `cd examples/toy_example && make`.

1. First we need to identify the addresses (or names) of the functions that send/receive messages within the executable. They can be as low-level as libc's `send` and `receive`, or possibly a more abstract function like `send_message` or `receive_message`. The key part here is to identify where are the message buffer and its length are stored within the program state, as well as what is the return value that indicates a successful send/receive of a message. We suggest doing so with a disassembler tool, like IDA.
   In our toy example we simply hook libc's `send` and `receive` functions.

2. Create a class to hook every function identified in (1). This class should implement the interface `Hook` that contains 3 methods:

   ```python
   class Hook:
       # This function should set the hook within the symbolic execution engine
       # In our case it gets the angr project with the executable loaded
       def set_hook(self, p):
           raise NotImplementedError()
   	
       # This function should extract the buffer pointer and the buffer length from the program state
       # It is given an instance of SimProcedure, which contains under hooker.state the program state
       def extract_arguments(self, hooker):
           raise NotImplementedError()
   
       # This function should return the suitable return address to simulate a successful send or receive
       # It is given the buffer, the length and the hooker (which contains the state)
       def get_return_value(self, buffer, length, hooker=None):
           raise NotImplementedError()
   ```

   In our toy example, we simply hook `send` and `receive`, which use the standard x86-64 calling convention. The functions should return the length of the provided buffer, to simulate a successful send or receive of the desired length.

   ```python
   from pise import hooks
   
   # Hook libc's send function
   # The first argument is the buffer, the second argument is its length.
   # The return value should be simply the length of the buffer
   class ToySendHook(hooks.Hook):
       def get_return_value(self, buff, length):
           return length
   
       def set_hook(self, p):
           p.hook_symbol('send', hooks.SendHook(self))
   
       def extract_arguments(self, hooker):
           # This send function uses the standard UNIX calling convention for x86
           length = hooker.state.regs.edx
           buffer = hooker.state.regs.rsi
           return buffer, length
   
   # Hook libc's receive function
   # The first argument is the buffer, the second argument is its length.
   # The return value should be simply the length of the buffer
   class ToyRecvHook(hooks.Hook):
       def get_return_value(self, buff, length):
           return length
   
       def set_hook(self, p):
           p.hook_symbol('recv', hooks.RecvHook(self))
   
       def extract_arguments(self, hooker):
           length = hooker.state.regs.edx
           buffer = hooker.state.regs.rsi
           return buffer, length
   ```

3. Finally, we should setup a query runner and a server to use that query runner. In our example it looks like:

   ```python
   query_runner = sym_execution.QueryRunner('toy_example', [ToySendHook(), ToyRecvHook()])
   server.Server(query_runner).listen()
   ```

   The server will start up, and listen on port 8080, ready to process queries from the learner module.
   The server for our toy example can be simply started with `python -m examples.toy_example.toy_client_inference`.

## Talks & Paper

The PISE paper is available [here](https://github.com/ron4548/InferenceServer/blob/master/paper.pdf).

Our Black Hat USA 2022 briefing is available [here](https://www.blackhat.com/us-22/briefings/schedule/#automatic-protocol-reverse-engineering-27238).

