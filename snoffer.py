from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP


def snoofer(dest_ip):
    ttl = 1
    count = 0
    temp_ip = ''

    while temp_ip != dest_ip:

        packet = IP(dst=dest_ip, ttl=ttl) / ICMP()

        print(packet.src)

        response = sr1(packet, filter='icmp', timeout=2)

        if response and IP in response:
            temp_ip = response[IP].src
            count += 1
            ttl += 1
        else:
            temp_ip = dest_ip

    print(f"{count} numbers of routers between {packet.src} to {dest_ip}")


if __name__ == '__main__':
    dest_ip = '8.8.8.8'

    snoofer(dest_ip)
