#!/usr/bin/python3 -tt
# coding=utf-8
#

import bbuzz
import json

# For 'raw2' a dictionary of the following values # is expected to form a Layer-2 frame:
# For 'raw3' a dictionary of string values # is expected to form a Layer-3 packet:

# Load JSON from file
with open('config.json', 'r') as file:
    config = json.load(file)

# Define the base Layer-2 connection
proto = bbuzz.protocol.Protocol(
        'raw3',
        {
            "SOURCE_IP": config["srcip4"],
            "DESTINATION_IP": config["dstip4"],
            "IP_VERSION": config["ipver4"],                
            "PROTO":config["l4proto_udp_num"],
            "SOURCE_MAC": config["srcmac"],
            "DESTINATION_MAC": config["dstmac"]
            }
        )

proto.create(config["interface"], config["l4proto_udp_num"])
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()

# UDP Header Fields
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

load.add('0008',  # Length
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
 

# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Sart fuzzing
print("[+] Starting fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)

