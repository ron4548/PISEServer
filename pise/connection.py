import json
import logging
import struct

logger = logging.getLogger(__name__)


# This class wraps a socket with json messages functionality
class Connection:
    def __init__(self, sock):
        self.sock = sock

    def recv_msg(self):
        msg_header_len = struct.calcsize(">I")
        msg_header = b''
        while msg_header_len != 0:
            chunk = self.sock.recv(msg_header_len)
            if len(chunk) == 0:
                logger.debug('Can\'t read msg header')
                return None
            msg_header_len -= len(chunk)
            msg_header += chunk

        msg_len = struct.unpack(">I", msg_header)[0]

        if msg_len == 0:
            logger.debug('Message length is 0')
            return None

        msg = b''
        while msg_len != 0:
            chunk = self.sock.recv(msg_len)
            msg += chunk
            msg_len -= len(chunk)

        logger.debug('Received %d bytes' % len(msg))
        return json.loads(msg.decode('utf-8'))

    def send_msg(self, msg):
        msg = json.dumps(msg).encode('utf-8')
        self.sock.sendall(struct.pack(">I", len(msg)) + msg)
        logger.debug('Sent %d bytes' % len(msg))

    def close(self):
        logger.debug('Closing connection')
        self.sock.close()
        self.sock = None
