import socket

from select import select
from icmp import build_packet, parse_packet
from icmp_type import ICMPType

from utils.sockets import create_tcp_socket, create_icmp_socket, BUFFER_SIZE


class Client(object):
    def __init__(self, tcp_listen_port: int, server_addr: str, target_host: str, target_port: int):
        self.server_addr = server_addr
        self.tcp_socket = create_tcp_socket()
        self.icmp_socket = create_icmp_socket()
        self.tcp_socket.bind(("0.0.0.0", tcp_listen_port))
        self.sockets = [self.tcp_socket, self.icmp_socket]
        self.target_host = socket.gethostbyname(target_host)
        self.target_port = target_port

    def start(self):
        while True:
            self.tcp_socket.listen(1)
            client_socket, _ = self.tcp_socket.accept()
            while True:
                ready_for_io_sockets, _, _ = select(self.sockets, [], [])
                for ready_for_io_socket in ready_for_io_sockets:
                    if ready_for_io_socket.proto == socket.IPPROTO_ICMP:
                        self.tunnel_to_client(ready_for_io_socket)
                    else:
                        self.client_to_tunnel(ready_for_io_socket)

    def tunnel_to_client(self, server_socket):
        server_socket_data = server_socket.recvfrom(BUFFER_SIZE)
        icmp_type, _, payload, _, _ = parse_packet(server_socket_data[0])
        # if packet.type == icmp.ICMP_ECHO_REQUEST:
        # Not our packet
        # return

        self.tcp_socket.send(payload)

    def client_to_tunnel(self, client_socket):
        client_socket_data = client_socket.recv(BUFFER_SIZE)
        icmp_packet = build_packet(ICMPType.ECHO_REQUEST, 0, client_socket_data, (self.target_host, self.target_port))
        self.icmp_socket.sendto(icmp_packet, (self.server_addr, 1))


def main():
    client = Client(8000, "server", "ynet.co.il", 443)
    client.start()


if __name__ == '__main__':
    main()
