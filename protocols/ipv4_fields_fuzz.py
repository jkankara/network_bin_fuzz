#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

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


# Layer-3 fuzzing example
# Define the base Layer-2 connection
print("[+] Setting up the base layer connection...")
proto = bbuzz.protocol.Protocol(
        'raw2',
        {
            "SOURCE_MAC": config["srcmac"],
            "DESTINATION_MAC": config["dstmac"],
            "ETHER_TYPE": "0x800"                  # IPv4
            }
        )
proto.create(config["interface"])

# Describe the Layer-3 payload - plain IPv6 header
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()

load.add('4',                                       # Version (IPv4)
        {
            "FORMAT": "dec",
            "TYPE": "static",
            "LENGTH": 4,
            "FUZZABLE": False
        }
        )
load.add('0101',                                    # IHL (Internet Header Length, e.g. 5 * 32 bits = 20 bytes)
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 4,
            "FUZZABLE": True
        }
        )
load.add('00000000',                                # Type of Service (DSCP + ECN)
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 8,
            "FUZZABLE": True
        }
        )
load.add('0014',                                    # Total Length (e.g. 0x003c = 60 bytes)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": False 
        }
        )
load.add('0000',                                    # Identification
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
        )
load.add('000',                                     # Flags (e.g., DF set)
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 3,
            "FUZZABLE": False
        }
        )
load.add('0000000000000',                           # Fragment Offset
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 13,
            "FUZZABLE": True
        }
        )
load.add('40',                                      # Time to Live (TTL)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
        )
load.add('06',                                      # Protocol (e.g., 6 = TCP)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
        )
load.add('0000',                                   # Header Checksum (can be recalculated or fuzzed)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": False
        }
        )
load.add(bbuzz.common.ip2bin('13.1.1.12'),        # Source IP
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 32,
            "FUZZABLE": False
        }
        )
load.add(bbuzz.common.ip2bin('13.1.1.11'),      # Destination IP
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 32,
            "FUZZABLE": False
        }
      )

# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Sart fuzzing
print("[+] Starting ipv4 fields fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)
