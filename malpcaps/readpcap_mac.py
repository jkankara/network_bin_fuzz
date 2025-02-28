#!/usr/bin/python3

import pyshark
import sys
import pandas as pd
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
limit_pkts = -1 #20000

def extract_ethernet_headers(packet):
    """
    Function to extract Ethernet (Layer 2) headers from a packet.

    Args:
        packet (pyshark.packet.packet.Packet): A single packet from the pcap file.

    Returns:
        dict: Contains Ethernet header information.
    """
    eth_header = "N/A"
    try:
        if hasattr(packet, 'eth'):
            eth_header = {
                'Source MAC': packet.eth.src,
                'Destination MAC': packet.eth.dst,
                'Type': packet.eth.type
            }

            # Check for optional fields
            if hasattr(packet.eth, 'len'):
                eth_header['Length'] = packet.eth.len
            else:
                eth_header['Length'] = 'N/A'

            if hasattr(packet.eth, 'checksum'):
                eth_header['Header Checksum'] = packet.eth.checksum
            else:
                eth_header['Header Checksum'] = 'N/A'
        else:
            eth_header = 'N/A'
    except:
        if hasattr(packet, 'llc'):
            print("its a llc pkt skipping ")
    return eth_header

def main(file_path):
    """
    Main function to read a pcap file and store Ethernet headers in a DataFrame.

    Args:
        file_path (str): Path to the pcap file.
    """
    global limit_pkts
    cap = pyshark.FileCapture(file_path)

    # Create an empty DataFrame
    df = pd.DataFrame(columns=['Source MAC', 'Destination MAC', 'Type', 'Length', 'Header Checksum'])
    i = 1 
    # Extract headers and store in DataFrame
    for packet in cap:
        print("packet# ", i) 
        eth_header = extract_ethernet_headers(packet)
        i += 1
        if eth_header != 'N/A':
            df = pd.concat([df, pd.DataFrame([eth_header])], ignore_index=True)
            limit_pkts -= 1
            if limit_pkts == 0: break

    # Print the DataFrame
    print(df)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_path>")
    else:
        file_path = sys.argv[1]
        main(file_path)

#import pyshark
#import sys
#
#def extract_ethernet_headers(packet):
#    """
#    Function to extract Ethernet (Layer 2) headers from a packet.
#
#    Args:
#        packet (pyshark.packet.packet.Packet): A single packet from the pcap file.
#
#    Returns:
#        dict: Contains Ethernet header information.
#    """
#    if hasattr(packet, 'eth'):
#        eth_header = {
#            'Source MAC': packet.eth.src,
#            'Destination MAC': packet.eth.dst,
#            'Type': packet.eth.type
#        }
#
#        # Check for optional fields
#        if hasattr(packet.eth, 'len'):
#            eth_header['Length'] = packet.eth.len
#        else:
#            eth_header['Length'] = 'N/A'
#
#        if hasattr(packet.eth, 'checksum'):
#            eth_header['Header Checksum'] = packet.eth.checksum
#        else:
#            eth_header['Header Checksum'] = 'N/A'
#    else:
#        eth_header = 'N/A'
#    return eth_header
#
#def main(file_path):
#    """
#    Main function to read a pcap file and print Ethernet headers in tabular form.
#
#    Args:
#        file_path (str): Path to the pcap file.
#    """
#    cap = pyshark.FileCapture(file_path)
#
#    # Print headers in tabular form
#    print("{:<20} {:<20} {:<20} {:<15} {:<20}".format(
#        'Source MAC', 'Destination MAC', 'Type', 'Length', 'Header Checksum'))
#    print("="*95)
#
#    for packet in cap:
#        eth_header = extract_ethernet_headers(packet)
#        if eth_header != 'N/A':
#            print("{:<20} {:<20} {:<20} {:<15} {:<20}".format(
#                eth_header['Source MAC'],
#                eth_header['Destination MAC'],
#                eth_header['Type'],
#                eth_header['Length'],
#                eth_header['Header Checksum']
#            ))
#        else:
#            print("No Ethernet header found in this packet.")
#
#if __name__ == "__main__":
#    if len(sys.argv) != 2:
#        print("Usage: python script.py <file_path>")
#    else:
#        file_path = sys.argv[1]
#        main(file_path)
