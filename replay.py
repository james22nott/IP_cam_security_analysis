import sys
from scapy.all import *

packets = rdpcap('captures/startpacketsonly.pcap')
sendp(packets, iface='wlp4s0')