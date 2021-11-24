import logging
import socket
import sys

from select import select
from icmp import build_packet, parse_packet
from icmp import ICMPType
from utils.sockets import create_icmp_server_socket, create_icmp_socket, create_tcp_socket, TCP_BUFFER_SIZE, \
    ICMP_BUFFER_SIZE

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class Server(object):
    def __init__(self) -> None:
        self.client_to_target_socket = create_icmp_server_socket()
        self.target_to_client_socket = create_icmp_socket()
        self.tcp_socket = None
        self.sockets = [self.client_to_target_socket]
        self.client_addr = None
        self.dest_addr = None
        self.dest_port = None

    def client_to_target(self) -> None:
        raw_packet, source_addr = self.client_to_target_socket.recvfrom(ICMP_BUFFER_SIZE)
        self.client_addr = source_addr[0]
        icmp_type, code, payload, self.dest_addr, self.dest_port = parse_packet(raw_packet)

        if icmp_type == ICMPType.ECHO_REQUEST and code == 1:
            if self.tcp_socket in self.sockets:
                self.sockets.remove(self.tcp_socket)
            if self.tcp_socket:
                self.tcp_socket.close()
            self.tcp_socket = None
            return

        if self.tcp_socket is None:
            logger.debug(f"Creating a new tcp socket to communicate with {self.dest_addr}")
            self.tcp_socket = create_tcp_socket()
            self.tcp_socket.connect((self.dest_addr, self.dest_port))
            self.sockets.append(self.tcp_socket)
        self.tcp_socket.send(payload)

    def target_to_client(self, target_socket: socket.socket):
        logger.debug("Received TCP packets from the target. Wrapping them in ICMP and forwarding to the client")
        try:
            target_data = target_socket.recv(TCP_BUFFER_SIZE)
        except Exception:
            return
        icmp_packet = build_packet(ICMPType.ECHO_REPLY, 0, target_data, self.dest_addr, self.dest_port)
        self.target_to_client_socket.sendto(icmp_packet, (self.client_addr, 0))

    def tunnel(self) -> None:
        logger.info("Started server. Waiting from incoming ICMP packets...")
        while True:
            ready_for_io_sockets, _, _ = select(self.sockets, [], [])
            for ready_for_io_socket in ready_for_io_sockets:
                if ready_for_io_socket.proto == socket.IPPROTO_ICMP:
                    self.client_to_target()
                else:
                    self.target_to_client(ready_for_io_socket)


def main():
    tunnel_server = Server()
    tunnel_server.tunnel()


if __name__ == '__main__':
    main()
