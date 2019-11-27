# Ettercap Network Analysis
Ettercap is used for packet captures and Man-in-the-Middle (MITM) attacks.
For this project we will be using Ettercap to ARP poison our subnet, thus
performing a MITM attack. We can do this by running the command
```bash
ettercap -M arp -i eth0 -o -T
```
 - The `-M arp` flag states that we want to perform a MITM attack via arp poison
 - The `-i eth0` flag states that we want to use our Ethernet interface
 - The `-o` flag states that we are only performing a MITM attack
 - The `-T` flag states that any output that Ettercap has should come to the CLI
After running the above command, we can open Wireshark and see the network
traffic for all machines on the subnet. We can see that Ettercap is performing
the ARP poisoning by repeatedly sending ARP reply frames to the other hosts
on the subnet saying that our machine's MAC address is the MAC for all the
IPs on the subnet. Causing traffic to be routed to us, and then we route it
to its intended destination.

# Nmap Scans
TBD

# Responder
TBD

# MS17-010 (CVE 2017-010)
TBD