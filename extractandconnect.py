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
            send_and_receive_data(connection, bytes(packet[Raw].load))

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

        # not quite sure why this is not printing the first part of the string
        print(f"Received and decoded data: {decoded_data} \n")

        # Define a regex pattern to find "type":"event"
        pattern = r'"conn_token"\s*:\s*"([^"]*)"'
        pattern2 = r'"media_ip"\s*:\s*"([^"]*)"'
        pattern3 = r'"media_port"\s*:\s*"([^"]*)"'

        # Use the regex pattern to find the "type" value
        match = re.search(pattern, decoded_data)
        match2 = re.search(pattern2, decoded_data)
        match3 = re.search(pattern3, decoded_data)

        if match:
            # If a match is found, extract the "type" value
            type_value = match.group(1)
            global token
            token = type_value
            print(f"Token: {token}")
        if match2:
            type_value2 = match2.group(1)
            global med_ip
            med_ip = type_value2
            print(f"Media IP: {med_ip}")
        if match3:
            type_value3 = match3.group(1)
            global med_port
            med_port = type_value3
            print(f"Media Port: {med_port}")
        

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
            modified_data = extracted_data.replace(
                b"1:1sc6bvvwaje9dlheni", token.encode("utf-8"))

            # Send the modified data to the server
            # print(f"Old data: {extracted_data}\n Modified message: {modified_data}\n")

            send_and_receive_data(connection, modified_data)
        else:
            # print(f"Token not found in extracted data: {extracted_data}\n")
            send_and_receive_data(connection, extracted_data)
            # pass


if __name__ == "__main__":
    global token
    global med_ip
    global med_port
    pcap_file = "captures/commands/authservertoconntoken.pcap"
    token = None
    med_ip = None
    med_port = None

    conn = establish_tcp_connection("18.218.23.115", 16035)
    extracted_data = extract_data_from_pcap(pcap_file, conn)
    close_tcp_connection(conn)

    if token is not None and med_ip is not None and med_port is not None:
        print(f"Token found: {token} \n")
        pcap_file = "captures/commands/toservernonvidnostart.pcap"
        conn = establish_tcp_connection(med_ip, int(med_port))
        modified_data = extract_modify_send(pcap_file, conn)
        close_tcp_connection(conn)
