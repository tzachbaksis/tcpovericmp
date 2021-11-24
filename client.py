import logging
import select
import socket
import sys

import icmp
from icmp_type import ICMPType
from utils.sockets import create_tcp_socket, create_icmp_socket, TCP_BUFFER_SIZE, ICMP_BUFFER_SIZE

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Port is not part of a ICMP packet, the number can even be randomized
PORT_IGNORED = 0


class ClientSession(object):
    def __init__(self, server: str, sock: socket.socket, target_host: str, target_port: int) -> None:
        self.server = server
        self.target_host = target_host
        self.target_port = target_port
        self.tcp_socket = sock
        self.icmp_socket = create_icmp_socket()
        self.sockets = [self.tcp_socket, self.icmp_socket]

    def start(self) -> None:
        logger.debug(f"New session started!")
        while True:
            socks, _, _ = select.select(self.sockets, [], [])
            for sock in socks:
                try:
                    self.server_to_client(sock) if sock.proto == socket.IPPROTO_ICMP else self.client_to_server(sock)
                except Exception:
                    self.finish_session()
                    return

    def server_to_client(self, sock: socket.socket) -> None:
        logger.debug(f"Received ICMP packets from the server. Parsing them and forwarding TCP to the client")
        target_icmp_data = sock.recvfrom(ICMP_BUFFER_SIZE)
        icmp_type, _, payload, _, _ = icmp.parse_packet(target_icmp_data[0])
        try:
            self.tcp_socket.send(payload)
        except (ConnectionResetError, BrokenPipeError):
            logger.debug("The client closed his TCP socket...")
            raise

    def client_to_server(self, sock: socket.socket) -> None:
        logger.debug(f"Received TCP packets from the client. Building the ICMP packets and sending to the server")
        try:
            client_data = sock.recv(TCP_BUFFER_SIZE)
            icmp_packet = icmp.build_packet(ICMPType.ECHO_REQUEST, 0, client_data, self.target_host, self.target_port)
            self.icmp_socket.sendto(icmp_packet, (self.server, PORT_IGNORED))
        except socket.error:
            logger.debug("The server closed its socket...")
            raise

    def finish_session(self) -> None:
        logger.debug(f"Finishing session...")
        self.tcp_socket.close()
        icmp_packet = icmp.build_packet(ICMPType.ECHO_REQUEST, 1, b"", self.target_host, self.target_port)
        self.icmp_socket.sendto(icmp_packet, (self.server, PORT_IGNORED))
        self.icmp_socket.close()


class Client(object):
    """
        A client used to allow TCP communication on TCP limited machines through ICMP tunneling.
        The client has two main goals:
            1. Receiving TCP packets from the client, wrapping them in ICMP and sending to the server (see `client_to_server`)
            2. Receiving ICMP packets from the server, parsing them and sending TCP back to the client (see `server_to_client`).
        """
    def __init__(self, server: str, local_port: int, target_host: str, target_port: int) -> None:
        logger.info(f"Starting client. Tunneling through: {server}, targeting: {target_host}:{target_port}...")
        self.server = server
        target_host = socket.gethostbyname(target_host)
        self.target_host, self.target_port = (target_host, target_port)
        self.tcp_server_socket = create_tcp_socket()
        self.tcp_server_socket.bind(("0.0.0.0", local_port))

    def start_listening(self) -> None:
        while True:
            self.tcp_server_socket.listen(5)
            sock, _ = self.tcp_server_socket.accept()
            session = ClientSession(self.server, sock, self.target_host, self.target_port)
            session.start()


if __name__ == "__main__":
    client = Client(
        server="server", local_port=8000,
        target_host="ynet.co.il", target_port=443
    )

    client.start_listening()
