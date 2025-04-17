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
            "PROTO":config["l3proto_icmp_num"],
            "SOURCE_MAC": config["srcmac"],
            "DESTINATION_MAC": config["dstmac"]
            }
        )

proto.create(config["interface"], config["l3proto_icmp_num"])
# Describe the Layer-3 payload - plain IPv6 header
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()


# ICMP Header Fields
load.add('08',  # Type (e.g., 8 for Echo Request)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
    )
load.add('00',  # Code (e.g., 0 for Echo Request)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
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
load.add('0001',  # Identifier
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )
load.add('0001',  # Sequence Number
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

