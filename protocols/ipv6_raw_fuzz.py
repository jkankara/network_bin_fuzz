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
with open('../config.json', 'r') as file:
    config = json.load(file)


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

load.add("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        {                                           #ipv4 header
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 320,
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
