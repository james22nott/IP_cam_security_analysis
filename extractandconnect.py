import socket
from scapy.all import *

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
    print(f"Received data: {received_data}")
    # search the received data for "conn_token" and return it
    conn_token = received_data.decode("utf-8")
    if "conn_token" in conn_token:
        conn_token = conn_token.split("token")[1]
        conn_token = conn_token.split("}")[0]
        conn_token = conn_token.split(":")[1]
        conn_token = conn_token.replace('"', "")
        return conn_token
    else:


    return received_data

if __name__ == "__main__":
    pcap_file = "captures/commands/old/ledflag2.pcap"
    conn = establish_tcp_connection("18.218.23.115", 16035)
    extracted_data = extract_data_from_pcap(pcap_file, conn)
    close_tcp_connection(conn)