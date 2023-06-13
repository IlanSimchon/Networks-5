from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP

# Define a fake source IP address
fake_ip = '1.2.3.4'

def icmp_spoofer(dest_ip):
    # Create a spoofed ICMP packet with the fake source IP and the specified destination IP
    spoofed_packet = IP(src=fake_ip, dst=dest_ip) / ICMP()

    # Send the spoofed ICMP packet
    send(spoofed_packet)

def udp_spoofer(dest_ip, udp_port):
    # Create a spoofed UDP packet with the fake source IP, the specified destination IP, and UDP port
    spoofed_packet = IP(src=fake_ip, dst=dest_ip) / UDP(dport=udp_port)

    # Send the spoofed UDP packet
    send(spoofed_packet)

def tcp_spoofer(dest_ip, tcp_port):
    # Create a spoofed TCP packet with the fake source IP, the specified destination IP, and TCP port
    spoofed_packet = IP(src=fake_ip, dst=dest_ip) / TCP(sport=1234, dport=tcp_port)

    # Send the spoofed TCP packet
    send(spoofed_packet)

if __name__ == '__main__':
    dest_ip = "10.9.5.58"
    port = 1234

    # Perform ICMP spoofing
    icmp_spoofer(dest_ip)

    # Perform UDP spoofing
    udp_spoofer(dest_ip, port)

    # Perform TCP spoofing
    tcp_spoofer(dest_ip, port)
