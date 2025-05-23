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
            "ETHER_TYPE": "0x86DD"                  # IPv6
            }
        )
proto.create(config["interface"])

# Describe the Layer-3 payload - plain IPv6 header
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()

load.add('6',                                       # Version number
        {
            "FORMAT": "dec",
            "TYPE": "static",
            "LENGTH": 4,
            "FUZZABLE": False
            }
        )
load.add('0',                                      # Traffic class
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 8,
            "FUZZABLE": True,
            }
        )
load.add('00000000000000000000',                    # Flow label
        {
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 20,
            "FUZZABLE": False
            }
        )
load.add('0000',                                    # Payload length
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 16,
            "FUZZABLE": False
            }
        )
load.add('11',                                      # Next header
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
            }
        )
load.add('ff',                                      # Hop limit
        {
            "FORMAT": "hex",
            "TYPE": "numeric",
            "LENGTH": 8,
            "FUZZABLE": True
            }
        )
load.add(bbuzz.common.ip2bin('fe80::10e9:d8ff:fe6a:e8f0'),
        {                                           # Source IP
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 128,
            "FUZZABLE": True
            }
        )
load.add(bbuzz.common.ip2bin('fe80::5054:ff:fe12:3456'),
        {                                           # Destination IP
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 128,
            "FUZZABLE": False
            }
        )

# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})

# Sart fuzzing
print("[+] Starting ipv6 fields fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)
