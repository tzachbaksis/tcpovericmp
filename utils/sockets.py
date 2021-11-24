import socket

TCP_BUFFER_SIZE = 2 ** 10
ICMP_BUFFER_SIZE = 65565


def create_icmp_socket():
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    return icmp_socket


def create_icmp_server_socket():
    icmp_server_socket = create_icmp_socket()
    icmp_server_socket.bind(("0.0.0.0", 0))
    icmp_server_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    return icmp_server_socket


def create_tcp_socket():
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return tcp_socket
