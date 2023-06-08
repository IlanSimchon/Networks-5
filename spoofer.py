from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP

fake_ip = '1.2.3.4'

def icmp_spoofer(dest_ip):
    spoofed_packet = IP(src=fake_ip, dst="10.9.1.198") / ICMP()

    send(spoofed_packet)


def udp_spoofer(dest_ip):
    spoofed_packet = IP(src=fake_ip, dst="10.9.1.198") / UDP(dport=1234)

    send(spoofed_packet)


def tcp_spoofer(dest_ip):
    spoofed_packet = IP(src=fake_ip, dst="10.9.1.198") / TCP(dport=80)

    send(spoofed_packet)


if __name__ == '__main__':

    dest_ip = "10.9.1.198"

    icmp_spoofer(dest_ip)
    udp_spoofer(dest_ip)
    tcp_spoofer(dest_ip)
