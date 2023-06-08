from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.inet6 import IPv6


def TCP_flow(pack):
    if pack[TCP].sport == 9999 or pack[TCP].dport == 9999:
        port_src = pack[TCP].sport
        port_dst = pack[TCP].dport

        if IP in pack:
            ip_src = pack[IP].src
            ip_dst = pack[IP].dst
        else:
            ip_src = 'None'
            ip_dst = 'None'

        flags = pack[TCP].flags
        cache_flag = (flags >> 12) & 1
        steps_flag = (flags >> 11) & 1
        type_flag = (flags >> 10) & 1
        status_code = flags & 0x3ff
        cache_control = pack[TCP].options[0][1]

        timestamp = pack.time
        total_len = len(pack)

        if Raw in pack:
            data = pack[Raw].load.hex()
        else:
            data = 'None'

        output = open("212036396_314770058.txt", 'a')
        output.write(f'source_ip: {ip_src}, dest_ip: {ip_dst}, source_port: {port_src},'
                     f'dest_port: {port_dst}, timestamp: {timestamp},total_length: {total_len},'
                     f' cache_flag: {cache_flag}, steps_flag:{steps_flag}, type_flag: {type_flag}, '
                     f'status_code:{status_code}, cache_control: {cache_control}, data: {data}\n')

        output.close()

    else:
        print(pack)
        if Raw in pack:
            data = 'data: ', str(pack[Raw].load.hex())
        else:
            data = ''
        if IP in pack:
            print(f'TCP packet from ip {pack[IP].src} on port {pack[TCP].sport} to ip {pack[IP].dst}'
                  f' on port {pack[TCP].dport} len {len(pack)} {data}')
        elif IPv6 in pack:
            print(f'TCP packet from ip {pack[IPv6].src} on port {pack[TCP].sport} to ip {pack[IPv6].dst}'
                  f' on port {pack[TCP].dport} len {len(pack)} {data}')
        else:
            print(f'TCP packet len {len(pack)}')


def UDP_flow(pack):
    if Raw in pack:
        data = 'data: ', str(pack[Raw].load.hex())
    else:
        data = ''

    if IP in pack:
        print(f'UDP packet from ip {pack[IP].src} on port {pack[UDP].sport} to ip {pack[IP].dst}'
              f' on port {pack[UDP].dport} len {len(pack)} {data}')
    elif IPv6 in pack:
        print(f'UDP packet from ip {pack[IPv6].src} on port {pack[UDP].sport} to ip {pack[IPv6].dst}'
              f' on port {pack[UDP].dport} len {len(pack)} {data}')
    else:
        print(f'UDP packet len {len(pack)}')


def ICMP_flow(pack):
    if Raw in pack:
        data = 'data: ', str(pack[Raw].load.hex())
    else:
        data = ''

    if IP in pack:
        print(f'ICMP packet from ip {pack[IP].src} on port {pack[ICMP].sport} to ip {pack[IP].dst}'
              f' on port {pack[ICMP].dport} len {len(pack)} {data}')
    elif IPv6 in pack:
        print(f'ICMP packet from ip {pack[IPv6].src} on port {pack[ICMP].sport} to ip {pack[IPv6].dst}'
              f' on port {pack[ICMP].dport} len {len(pack)} {data}')
    else:
        print(f'ICMP packet len {len(pack)}')


def IGMP_flow(pack):
    if Raw in pack:
        data = 'data: ', str(pack[Raw].load.hex())
    else:
        data = ''

    if IP in pack:
        print(f'IGMP packet from ip {pack[IP].src} to ip {pack[IP].dst}'
              f' len {len(pack)} {data}')

    elif IPv6 in pack:
        print(f'IGMP packet from ip {pack[IPv6].src} to ip {pack[IPv6].dst}'
              f' len {len(pack)} {data}')
    else:
        print(f'IGMP packet len {len(pack)}')


def default_flow(pack):
    print(f'default type of packet len {len(pack)}')


def sniffer(pack):
    if pack.haslayer(TCP):
        TCP_flow(pack)
    elif pack.haslayer(UDP):
        UDP_flow(pack)
    elif pack.haslayer(ICMP):
        ICMP_flow(pack)
    elif pack.haslayer(IGMP):
        IGMP_flow(pack)
    else:
        default_flow(pack)
    print()


def main():
    try:
        sniff(prn=sniffer , iface='lo')
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
