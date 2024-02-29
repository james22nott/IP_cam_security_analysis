import socket
from scapy.all import *
import json
import re

def extract_data_from_pcap(pcap_file, connection):
    # Read the PCAP file
    packets = rdpcap(pcap_file)

    # Extract data from the packets (modify this based on your needs)
    extracted_data = b''
    for packet in packets:
        # Assuming the data is in the payload of TCP packets
        if TCP in packet and Raw in packet:
            send_and_receive_data(connection,bytes(packet[Raw].load))

    return extracted_data


def establish_tcp_connection(ip_address, port):
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
    # print(f"Received data: {received_data}")

    try:
        # Decode the received data as UTF-8
        decoded_data = received_data.decode("utf-8", errors="ignore")

        # Handle non-UTF-8 characters
        decoded_data = "".join(
            c if ord(c) < 128 else f"\\x{ord(c):02x}" for c in decoded_data
        )

        print("Decoded data:")
        print(f"Decoded data: {decoded_data}\n")

        # Define a regex pattern to find "type":"event"
        pattern = r'"type"\s*:\s*"([^"]*)"'

        # Use the regex pattern to find the "type" value
        match = re.search(pattern, decoded_data)

        if match:
            # If a match is found, extract the "type" value
            type_value = match.group(1)
            print("found type: ")
            print(type_value)
            global token
            token = type_value
            return type_value
        else:
            print("No 'type' found in the decoded data.")

    except UnicodeDecodeError:
        # Handle decoding errors by ignoring the data
        print("Error decoding data as UTF-8. Ignoring...")
        return received_data

def extract_modify_send(pcap_file, connection):
    # Read the PCAP file
    packets = rdpcap(pcap_file)

    # Extract data from the packets (modify this based on your needs)
    extracted_data = b''
    for packet in packets:
        # Assuming the data is in the payload of TCP packets
        if TCP in packet and Raw in packet:
            extracted_data = packet[Raw].load

        # Modify the extracted data (modify this based on your needs)
        global token
        # modify the data to replace 1:1sc6bvvwaje9dlheni with the token
        if b"1:1sc6bvvwaje9dlheni" in extracted_data:
            print("Token found in extracted data. Modifying...")
            modified_data = extracted_data.replace(b"1:1sc6bvvwaje9dlheni", token.encode("utf-8"))

            # Send the modified data to the server
            send_and_receive_data(connection, modified_data)
        else:
            send_and_receive_data(connection, extracted_data)

    return modified_data


if __name__ == "__main__":
    global token
    pcap_file = "captures/commands/authservertoconntoken.pcap"
    token = None
    
    conn = establish_tcp_connection("18.218.23.115", 16035)
    extracted_data = extract_data_from_pcap(pcap_file, conn)
    close_tcp_connection(conn)

    if token is not None:
        print("token found: ")
        print(token, "\n")

        pcap_file = "captures/commands/toservernonvid.pcap"
        conn = establish_tcp_connection("35.203.181.109", 22045)
        modified_data = extract_modify_send(pcap_file, conn)
        close_tcp_connection(conn)
