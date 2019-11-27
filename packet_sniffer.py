'''
Authors: James Barr, Demarcus Campbell, Tucker Simpson
'''

from scapy.all import *
import sys

'''
Returns dictionary of all levels' headers, and application data
{"frame_header":..., "arp/ip_header":, "tcp/udp_header":...,"raw_data":...}
param: None
returns: dict packet_information
'''
def get_packet():
    packet_information = dict()
    packet = sniff(store=1, count=1)[0]
    packet_information["frame_header"] = packet.getlayer(Ether)
    if packet.type == 2054:
        packet_information["arp_header"] = packet.getlayer(ARP)
        packet_information["padding"] = packet.getlayer(Padding)
    else:
        if packet.type == 2048: # IPv4
            packet_information["ip_header"] = packet.getlayer(IP)
            if packet_information["ip_header"].proto == 6:
                packet_information["tcp_header"] = packet.getlayer(TCP)
                packet_information["raw_data"] = packet.getlayer(Raw)
            elif packet_information["ip_header"].proto == 17:
                packet_information["udp_header"] = packet.getlayer(UDP)
                packet_information["raw_data"] = packet.getlayer(Raw)
            elif packet_information["ip_header"].proto == 1:
                packet_information["icmp_header"] = packet.getlayer(ICMP)
                packet_information["raw_data"] = packet.getlayer(Raw)
            else: # Packet not TCP, UDP, or ICMP
                return get_packet()
        elif packet.type == 34525: # IPv6
            packet_information["ipv6_header"] = packet.getlayer(IPv6)
            if packet_information["ipv6_header"].nh == 6:
                packet_information["tcp_header"] = packet.getlayer(TCP)
                packet_information["raw_data"] = packet.getlayer(Raw)
            elif packet_information["ipv6_header"].nh == 17:
                packet_information["udp_header"] = packet.getlayer(UDP)
                packet_information["raw_data"] = packet.getlayer(Raw)
            #elif packet_information["ipv6_header"].nh == 58:
            #    packet_information["icmp_header"] = packet.getlayer(_ICMPv6)
            #    packet_information["raw_data"] = packet.getlayer(Raw)
            else: # Packet not TCP or UDP
                get_packet()
        else: # Packet not ARP or IP
            return get_packet()

    return packet_information
    
if __name__ == "__main__":
    print(get_packet())
        