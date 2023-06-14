from scapy.all import *
from scapy.layers.inet import ICMP, IP

fake_ip = '1.2.3.4'


def snoffer(packet):
    if packet[ICMP].type == 8:
        packet = IP(src=packet[IP].dst, dst=packet[IP].src)
        icmp = ICMP(type=0, code=0)

        icmp_pack = packet / icmp

        send(icmp_pack)


if __name__ == '__main__':
    sniff(filter='icmp', prn=snoffer, iface='br-e7af8d3b78f')
