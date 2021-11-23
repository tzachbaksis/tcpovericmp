import struct
import socket

from icmp_checksum import ICMPChecksum
from icmp_type import ICMPType

ICMP_STRUCT = "!BBHHH4sH"


def build_packet(icmp_type: ICMPType, code: int, payload: bytes, dest_ip: str, dest_port: int) -> bytes:
    """
    Build ICMP packet using struct module, based on the following structure:

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type(8)   |     Code(0)   |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Payload                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    icmp_struct_unpacked = [icmp_type.value, code, 0, 0, 0, socket.inet_aton(dest_ip), dest_port]
    icmp_struct_str = _add_payload(payload, icmp_struct_unpacked)
    packet_without_checksum = struct.pack(icmp_struct_str, *icmp_struct_unpacked)
    checksum = ICMPChecksum(packet_without_checksum).calculate()
    icmp_struct_unpacked[2] = checksum
    return struct.pack(icmp_struct_str, *icmp_struct_unpacked)


def parse_packet(packet: bytes) -> tuple:
    icmp_struct_str = ICMP_STRUCT
    payload = b""

    # first 20 bytes are IP, we'll skip them right to the ICMP bytes
    icmp_packet = packet[20:]

    icmp_struct_size = struct.calcsize(icmp_struct_str)
    packet_len = len(icmp_packet) - icmp_struct_size

    if packet_len > 0:
        icmp_payload_str = f"{packet_len}s"
        payload = struct.unpack(icmp_payload_str, icmp_packet[icmp_struct_size:])[0]

    icmp_type, code, checksum, _, _, dest_ip, dest_port = struct.unpack(icmp_struct_str, icmp_packet[:icmp_struct_size])
    return ICMPType(icmp_type), code, payload, socket.inet_ntoa(dest_ip), dest_port


def _add_payload(payload: bytes, icmp_struct_unpacked: list) -> str:
    icmp_struct_str = ICMP_STRUCT
    if payload:
        icmp_struct_str += "{}s".format(len(payload))
        icmp_struct_unpacked.append(payload)
    return icmp_struct_str
