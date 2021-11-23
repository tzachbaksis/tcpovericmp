import socket

from select import select
from icmp import build_packet, parse_packet
from icmp import ICMPType
from utils.sockets import create_icmp_server_socket, create_icmp_socket, BUFFER_SIZE, create_tcp_socket


class Server(object):
    def __init__(self):
        self.client_to_target_socket = create_icmp_server_socket()
        self.target_to_client_socket = create_icmp_socket()
        self.tcp_socket = create_tcp_socket()
        self.sockets = [self.client_to_target_socket]
        self.client_addr = None
        self.dest_addr = None
        self.dest_port = None

    def client_to_target(self):
        raw_packet, source_addr = self.client_to_target_socket.recvfrom(BUFFER_SIZE)
        self.client_addr = source_addr[0]
        icmp_type, code, payload, self.dest_addr, self.dest_port = parse_packet(raw_packet)

        if icmp_type == ICMPType.ECHO_REPLY and code != ICMPType.ECHO_REQUEST:
            print("Received ICMP packet with type different from echo request. Ignoring")
            return

        self.tcp_socket.connect((self.dest_addr, self.dest_port))
        if self.tcp_socket not in self.sockets:
            self.sockets.append(self.tcp_socket)
        self.tcp_socket.send(payload)

    def target_to_client(self, target_socket):
        target_data = target_socket.recv(BUFFER_SIZE)
        icmp_packet = build_packet(ICMPType.ECHO_REPLY, 0, target_data, self.dest_addr, self.dest_port)
        self.target_to_client_socket.sendto(icmp_packet, (self.client_addr, 0))

    def tunnel(self):
        print("start listening")
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
