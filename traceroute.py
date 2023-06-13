from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP


def traceroute(dest_ip):
    ttl = 1
    count = 0
    temp_ip = ''

    while temp_ip != dest_ip:
        # Create an ICMP packet with the specified destination IP and TTL
        packet = IP(dst=dest_ip, ttl=ttl) / ICMP()

        # Send the packet and wait for a response
        response = sr1(packet, filter='icmp', timeout=2)

        if response and IP in response:
            # If a response is received and it contains IP layer
            temp_ip = response[IP].src
            count += 1
            ttl += 1
        else:
            temp_ip = dest_ip

    # Print the number of routers encountered and the source and destination IPs
    print(f"{count} numbers of routers between {packet.src} to {dest_ip}")


if __name__ == '__main__':
    dest_ip = '8.8.8.8'

    # Perform traceroute to the specified destination IP
    traceroute(dest_ip)
