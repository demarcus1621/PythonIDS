'''
Authors: James Barr, Demarcus Campbell, Tucker Simpson
'''

from scapy.all import *

class project_ids:

    # gratuitous ARP pings threshold to help detect ARP poisoning
    __gratuitous_arp_threshold = 100
    
    # ARP cache built over time from sniffed ARP pings
    __arp_cache = dict()
    
    # Port connections map to help detect nmap Syn scan
    __port_connections = dict()
    
    def packet_checks(self, packet):
        if packet.haslayer(ARP):
            self.arp_poison_check(packet)
        elif packet.haslayer(TCP):
            self.nmap_syn_check(packet)
        
    '''
    Works under the assumption of gratuitous ARPs not being normal for the
    network. Counts gratuitous ARP pings until threshold of 100 is reached,
    then prints to screen that possible ARP poison has happened.
    '''
    def arp_poison_check(self, packet):
        frame = packet.getlayer(Ether)
        if frame.dst != 'ff:ff:ff:ff':
            arp_reply = frame.src + " " + frame.dst
            if arp_reply in type(self).__arp_cache:
                type(self).__arp_cache[arp_reply] += 1
            else:
                type(self).__arp_cache[arp_reply] = 1
        
        for reply in type(self).__arp_cache:
            if type(self).__gratuitous_arp_threshold <= type(self).__arp_cache[reply]:
                print("Possible ARP poison from ", reply.split()[0])
                # return True
    
    '''
    Works under the assumption that connection port reuse is unlikely in
    short periods of time. Nmap Syn scans without obfuscation tatics in
    place will exhibit numerous Syn's from a singular port to all of the
    different scanned ports.
    '''
    def  nmap_syn_check(self, packet):
        tcp_header = packet.getlayer(TCP)
        if tcp_header.sport in type(self).__port_connections:
            if tcp_header.dport not in type(self).__port_connections[tcp_header.sport]:
                type(self).__port_connections[tcp_header.sport] = type(self).__port_connections[tcp_header.sport] + [tcp_header.dport]
                # The above works because Python wants to be magical with the list().append() method
        else:
            type(self).__port_connections[tcp_header.sport] = [tcp_header.dport]
            
        for connection in type(self).__port_connections:
            if len(type(self).__port_connections[connection]) > 5:
                print("Possible NMAP Syn scan from ", packet.getlayer(IP).src, " on ", packet.getlayer(IP).dst)
    
if __name__ == "__main__":
    sniff(prn=project_ids().packet_checks)