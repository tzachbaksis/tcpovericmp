class ICMPChecksum(object):
    def __init__(self, packet: bytes):
        self.packet = packet
        self.length = len(packet)

    def calculate(self):
        """
        Based on RFC1071: https://tools.ietf.org/html/rfc1071, return the checksum of the ICMP packet
        """
        temp_checksum = 0
        count_to = (self.length / 2) * 2
        count = 0

        while count < count_to - 1:
            val = self.packet[count + 1] * 256 + self.packet[count]
            temp_checksum = temp_checksum + val
            temp_checksum = temp_checksum & 0xffffffff
            count = count + 2

        if count_to < self.length:
            temp_checksum = temp_checksum + self.packet[self.length - 1]
            temp_checksum = temp_checksum & 0xffffffff

        temp_checksum = (temp_checksum >> 16) + (temp_checksum & 0xffff)
        temp_checksum = temp_checksum + (temp_checksum >> 16)
        checksum = ~temp_checksum
        checksum = checksum & 0xffff
        checksum = checksum >> 8 | (checksum << 8 & 0xff00)
        return checksum
