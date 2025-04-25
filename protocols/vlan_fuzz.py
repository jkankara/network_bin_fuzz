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
        'raw1',
        {
            "SOURCE_MAC": config["srcmac"],
            "DESTINATION_MAC": config["dstmac"],
#            "ETHER_TYPE": "0x800"                  # IPv4
            }
        )
proto.create(config["interface"])

# Describe the Layer-3 payload - plain IPv6 header
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()

# VLAN Tag Control Information (TCI)


load.add("0x8100",  # Default EtherType (IPv4)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,  # EtherType is 16 bits
            "FUZZABLE": True
        }
    ) 

load.add("000",  # Priority Code Point (PCP)
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 3,  # PCP is 3 bits
            "FUZZABLE": True
        }
    )
load.add("0",  # Drop Eligible Indicator (DEI)
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 1,  # DEI is 1 bit
            "FUZZABLE": True
        }
    )
load.add("0100",  # VLAN Identifier (VID)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 12,  # VID is 12 bits
            "FUZZABLE": True
        }
    )


load.add("1111111111111111000000",
        {                                           #ipv4 header 
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 64,
            "FUZZABLE": True
            }
        )


# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Sart fuzzing
print("[+] Starting Ethernet protocol fuzzing ...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)
