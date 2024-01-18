from scapy.all import *

def adjust_sequence_numbers(packet_list, offset):
    for packet in packet_list:
        if TCP in packet:
            packet[TCP].seq += offset
        yield packet

# Load the original capture file
original_packets = rdpcap("captures/lightcommand.pcap")

# Adjust sequence numbers by a specified offset
adjusted_packets = adjust_sequence_numbers(original_packets, 1000)

# Save the modified capture file
wrpcap("captures/modifiedcommand.pcap", adjusted_packets)
