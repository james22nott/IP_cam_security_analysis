import socket
from scapy.all import *


def extract_data_from_pcap(pcap_file):
    # Read the PCAP file
    packets = rdpcap(pcap_file)

    # Extract data from the packets (modify this based on your needs)
    extracted_data = b''
    for packet in packets:
        # Assuming the data is in the payload of TCP packets
        if TCP in packet and Raw in packet:
            extracted_data += bytes(packet[Raw].load)

    return extracted_data


def establish_tcp_connection(data):
    # IP address and port of the recipient
    ip_address = "18.222.28.202"
    port = 16035

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect((ip_address, port))
        print(f"Connected to {ip_address}:{port}")

        # You can send/receive data here if needed
        client_socket.sendall(data)
        print(f"Data sent: {data}")
        received_data = client_socket.recv(1024)
        print(f"Received data: {received_data}")

    except socket.error as e:
        print(f"Connection failed: {e}")

    finally:
        # Close the socket
        client_socket.close()
        print("Connection closed")

if __name__ == "__main__":
    pcap_file = "captures/justlogin.pcap"
    data = extract_data_from_pcap(pcap_file)
    establish_tcp_connection(data)
