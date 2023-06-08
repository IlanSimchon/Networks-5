import random
import struct
import socket


def calculate_checksum(data):
    checksum = 0
    if len(data) % 2 == 1:
        data += b'\x00'
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    checksum = ~checksum & 0xFFFF
    return checksum


def send_packet(protocol: str, packet, dest_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        sock.sendto(packet, (dest_ip, 0))

        sock.close()
        print(f'spoofing packets on {protocol} protocol successful')

    except:
        print(f'Error in spoofing packets in the {protocol} protocol')


def icmp_spoofer(dest_ip):
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_identifier = 6453
    icmp_sequence = 1
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)

    icmp_checksum = calculate_checksum(icmp_header)

    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)

    ip_header = struct.pack("!BBHHHBBH4s4s", 69, 0, 28, 54321, 0, 64, 1, 0, socket.inet_aton("1.2.3.4"),
                            socket.inet_aton(dest_ip))

    packet = ip_header + icmp_header
    send_packet('ICMP', packet, dest_ip)


def udp_spoofer(dest_ip):
    source_port = 1122
    dest_port = 53
    length = 8
    checksum = 0

    udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)

    ip_version = 4
    ip_header_length = 5
    total_length = 20 + length
    aton_source_ip = socket.inet_aton('1.2.3.4')
    aton_dest_ip = socket.inet_aton(dest_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s', (ip_version << 4) + ip_header_length, 0, total_length, 54321,
                            0, 64, socket.IPPROTO_UDP, checksum, aton_source_ip, aton_dest_ip)

    packet = ip_header + udp_header

    send_packet('UDP', packet, dest_ip)

def tcp_spoofer(dest_ip):
    source_ip = '1.2.3.4'
    source_port = 1122
    dest_port = 1234
    sequence_number = 123456789
    acknowledgment_number = 0
    data_offset = 5
    flags = 2
    window_size = socket.htons(8192)
    checksum = 0
    urgent_pointer = 0

    tcp_header = struct.pack('!HHIIBBHHH', source_port, dest_port, sequence_number,
                             acknowledgment_number, (data_offset << 4), flags, window_size,
                             checksum, urgent_pointer)
    ip_version = 4
    ip_header_length = 5
    total_length = len(tcp_header)
    aton_source_ip = socket.inet_aton(source_ip)
    aton_dest_ip = socket.inet_aton(dest_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s', (ip_version << 4) + ip_header_length, 0,
                            total_length, 0, 0, 6, 0, 0, aton_source_ip,
                            aton_dest_ip)
    checksum = calculate_checksum(tcp_header)

    tcp_header = struct.pack('!HHIIBBHHH', source_port, dest_port, sequence_number,
                             acknowledgment_number, (data_offset << 4), flags, window_size,
                             checksum, urgent_pointer)

    packet = ip_header + tcp_header

    send_packet('TCP', packet, dest_ip)


if __name__ == '__main__':

    dest_ip = "10.9.1.198"

    icmp_spoofer(dest_ip)
#    udp_spoofer(dest_ip)
 #   tcp_spoofer(dest_ip)
