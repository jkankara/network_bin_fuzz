#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import bbuzz
import json

# Load JSON from file
with open('config.json', 'r') as file:
    config = json.load(file)


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
load.add('0000',                                    # IHL (Internet Header Length, e.g. 5 * 32 bits = 20 bytes)
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
load.add('003c',                                    # Total Length (e.g. 0x003c = 60 bytes)
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
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
load.add('010',                                     # Flags (e.g., DF set)
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 3,
            "FUZZABLE": True
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
            "FUZZABLE": True
        }
        )
load.add(bbuzz.common.ip2bin('13.1.1.12'),        # Source IP
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 32,
            "FUZZABLE": True
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
print("[+] Starting fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)
