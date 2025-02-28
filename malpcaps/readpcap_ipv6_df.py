#!/usr/bin/python3

import pyshark
import sys
import pandas as pd

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
limit_pkts = 20000

def extract_ipv6_headers(packet):
    """
    Function to extract IPv6 (Layer 3) headers from a packet.

    Args:
        packet (pyshark.packet.packet.Packet): A single packet from the pcap file.

    Returns:
        dict: Contains IPv6 header information.
    """
    ipv6_header = 'N/A'
    try:
        if hasattr(packet, 'ipv6'):
            ipv6_header = {
                'Source IP': packet.ipv6.src,
                'Destination IP': packet.ipv6.dst,
                'Version': packet.ipv6.version
            }

            if hasattr(packet.ipv6, 'traffic_class'):
                ipv6_header['Traffic Class'] = packet.ipv6.traffic_class
            else:
                ipv6_header['Traffic Class'] = 'N/A'

            if hasattr(packet.ipv6, 'flow_label'):
                ipv6_header['Flow Label'] = packet.ipv6.flow_label
            else:
                ipv6_header['Flow Label'] = 'N/A'

            if hasattr(packet.ipv6, 'payload_length'):
                ipv6_header['Payload Length'] = packet.ipv6.payload_length
            else:
                ipv6_header['Payload Length'] = 'N/A'

            if hasattr(packet.ipv6, 'next_header'):
                ipv6_header['Next Header'] = packet.ipv6.next_header
            else:
                ipv6_header['Next Header'] = 'N/A'

            if hasattr(packet.ipv6, 'hop_limit'):
                ipv6_header['Hop Limit'] = packet.ipv6.hop_limit
            else:
                ipv6_header['Hop Limit'] = 'N/A'
        else:
            ipv6_header = 'N/A'
    except:
        print("not a ethernet packet", packet)
    return ipv6_header

def main(file_path):
    """
    Main function to read a pcap file and store IPv6 headers in a DataFrame.

    Args:
        file_path (str): Path to the pcap file.
    """
    global limit_pkts
    cap = pyshark.FileCapture(file_path)

    # Create an empty DataFrame
    df = pd.DataFrame(columns=['Source IP', 'Destination IP', 'Version', 'Traffic Class', 'Flow Label',
                               'Payload Length', 'Next Header', 'Hop Limit'])

    # Extract headers and store in DataFrame
    for packet in cap:
        ipv6_header = extract_ipv6_headers(packet)
        if ipv6_header != 'N/A':
            df = pd.concat([df, pd.DataFrame([ipv6_header])], ignore_index=True)
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
