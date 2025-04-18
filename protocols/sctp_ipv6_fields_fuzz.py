#!/usr/bin/python3 -tt
# coding=utf-8
#

import bbuzz
import json
import os

# Dynamically locate config.json relative to the run_all.py script
script_dir = os.path.dirname(os.path.abspath(__file__))  # Directory of ethernet_fuzz.py
config_path = os.path.join(script_dir, "..", "config.json")

# Load JSON from file
try:
    with open(config_path, 'r') as file:
        config = json.load(file)
except FileNotFoundError:
    print(f"[!] config.json not found at {config_path}. Exiting.")
    exit(1)

# Define the base Layer-3 connection
proto = bbuzz.protocol.Protocol(
        'raw3',
        {
            "SOURCE_IP": config["srcip6"],
            "DESTINATION_IP": config["dstip6"],
            "IP_VERSION": config["ipver6"],                
            "PROTO":config["l4proto_sctp_num"],
            "SOURCE_MAC": config["srcmac"],
            "DESTINATION_MAC": config["dstmac"]
            }
        )

proto.create(config["interface"], config["l4proto_sctp_num"])
# Describe the Layer-3 payload - plain IPv6 header
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()

load.add(config["srcport"],
        {                                           # Source Port
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
            }
        )

load.add(config["dstport"],
        {                                           # dst Port
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
            }
        )

load.add("ff",
        {                                           # ver tag
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 32,
            "FUZZABLE": True
            }
        )

load.add("ff",
        {                                           # checksum
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 32,
            "FUZZABLE": True
            }
        )


# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Sart fuzzing
print("[+] Starting sctp ipv6 fields fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)

