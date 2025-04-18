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
            "PROTO":config["l4proto_udp_num"],
            "SOURCE_MAC": config["srcmac"],
            "DESTINATION_MAC": config["dstmac"]
            }
        )

proto.create(config["interface"], config["l4proto_udp_num"])
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()

# UDP Header
load.add('0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',  # Source Port
        {
            "FORMAT": "bin",
            "TYPE": "numeric",
            "LENGTH": 160,
            "FUZZABLE": True
        }
    )

# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Sart fuzzing
print("[+] Starting udp ipv6 raw fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)

