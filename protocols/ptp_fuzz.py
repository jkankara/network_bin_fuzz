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

# EtherType for PTP (0x88F7) - NOT FUZZABLE as per requirement
load.add("0x88F7",  # PTP EtherType
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,  # EtherType is 16 bits
            "FUZZABLE": False
        }
    )

# PTP Header Fields (34 bytes total for common header)
# All fields are FUZZABLE except EtherType

# transportSpecific (4 bits) + messageType (4 bits) = 1 byte
load.add("0x00",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
    )

# reserved (4 bits) + versionPTP (4 bits) = 1 byte
load.add("0x02",  # PTP version 2
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
    )

# messageLength (2 bytes)
load.add("0x002C",  # 44 bytes typical for Sync message
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )

# domainNumber (1 byte)
load.add("0x00",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
    )

# reserved (1 byte)
load.add("0x00",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
    )

# flagField (2 bytes)
load.add("0x0000",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )

# correctionField (8 bytes)
load.add("0x0000000000000000",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 64,
            "FUZZABLE": True
        }
    )

# reserved (4 bytes)
load.add("0x00000000",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 32,
            "FUZZABLE": True
        }
    )

# sourcePortIdentity - clockIdentity (8 bytes)
load.add("0x0000000000000000",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 64,
            "FUZZABLE": True
        }
    )

# sourcePortIdentity - portNumber (2 bytes)
load.add("0x0001",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )

# sequenceId (2 bytes)
load.add("0x0000",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": True
        }
    )

# controlField (1 byte)
load.add("0x00",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
    )

# logMessageInterval (1 byte)
load.add("0x7F",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
        }
    )

# PTP Message-specific fields (for Sync message - 10 bytes)

# originTimestamp - seconds (6 bytes / 48 bits)
load.add("0x000000000000",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 48,
            "FUZZABLE": True
        }
    )

# originTimestamp - nanoseconds (4 bytes)
load.add("0x00000000",
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 32,
            "FUZZABLE": True
        }
    )

# Generate payload mutations
print("[+] Generating PTP mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Start fuzzing
print("[+] Starting PTP (IEEE 1588) protocol fuzzing...")
print("[+] EtherType 0x88F7 is fixed, all other fields will be fuzzed")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)
