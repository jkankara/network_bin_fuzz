#!/usr/bin/python3 -tt
# coding=utf-8
#

import bbuzz
import json

# For 'raw2' a dictionary of the following values # is expected to form a Layer-2 frame:
# For 'raw3' a dictionary of string values # is expected to form a Layer-3 packet:

# Load JSON from file
with open('../config.json', 'r') as file:
    config = json.load(file)

# Define the base Layer-2 connection
proto = bbuzz.protocol.Protocol(
        'raw3',
        {
            "SOURCE_IP": config["srcip6"],
            "DESTINATION_IP": config["dstip6"],
            "IP_VERSION": config["ipver6"],                
            "PROTO":config["l4proto_tcp_num"],
            "SOURCE_MAC": config["srcmac"],
            "DESTINATION_MAC": config["dstmac"]
            }
        )

proto.create(config["interface"], config["l4proto_tcp_num"])
# Describe the Layer-3 payload - plain IPv6 header
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()

# TCP Header Fields
load.add('0000',  # Source Port
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )
load.add('0000',  # Destination Port
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )
load.add('00000000',  # Sequence Number
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 32,
            "FUZZABLE": True
        }
    )
load.add('00000000',  # Acknowledgment Number
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 32,
            "FUZZABLE": True
        }
    )
load.add('5',  # Data Offset (Header Length)
        {
            "FORMAT": "dec",
            "TYPE": "static",
            "LENGTH": 4,
            "FUZZABLE": False
        }
    )
load.add('000',  # Reserved
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 3,
            "FUZZABLE": False
        }
    )
load.add('000000',  # Flags (e.g., SYN, ACK, etc.)
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 6,
            "FUZZABLE": True
        }
    )
load.add('0000',  # Window Size
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )
load.add('0000',  # Checksum
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": False
        }
    )
load.add('0000',  # Urgent Pointer
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )

# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Sart fuzzing
print("[+] Starting fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)

