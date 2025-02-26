#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import bbuzz

# For 'raw2' a dictionary of the following values # is expected to form a Layer-2 frame:
# "SOURCE_MAC": "STR_MAC_ADDRESS" | # "DESTINATION_MAC": "STR_MAC_ADDRESS"
# "ETHER_TYPE": "STR_0xETHER_TYPE" |
# .1Q VLAN tagging information together with the
# ETHER_TYPE.

# For 'raw3' a dictionary of string values # is expected to form a Layer-3 packet:
# "SOURCE_IP": "STR_IP_ADDRESS"   | # "DESTINATION_IP": "STR_IP_ADDRESS" | # "IP_VERSION": INT_IP_VERSION

# For 'raw4' a dictionary of the follwoing values  ((DESTINATION_IP, DESTINATION_PORT), PROTO) # is expected to form a a Layer-4 packet/datagram:
# "DESTINATION_IP": "STR_IP_ADDRESS"
# "SOURCE_IP": "STR_IP_ADDRESS"
# "IP_VERSION": INT_IP_VERSION
# "PROTO": INT_0xPROTO_NUMBER (e.g., UDP=0x11, TCP=0x06)
# "DESTINATION_PORT": INT_PORT_NUMBER
# "SOURCE_PORT": INT_PORT_NUMBER
# "BROADCAST": BOOL_TURE-FALSE

# Define the base Layer-2 connection
interface = "enp216s0f1"
srcmac, dstmac = '00:1b:21:87:a9:d5', "00:1b:21:67:65:a9"
srcip, dstip = "fe80::200:ff:fe00:401", "fe80::e2b7:6ba:5d30:8b21"
ipver = 6
proto = 0x84
dstport, srcport = "2900", "9000"
l4proto = "IPPROTO_SCTP" #IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP

proto = bbuzz.protocol.Protocol(
        'raw3',
        {
            "IP_VERSION": 6,                  # IPv6
            "SOURCE_IP": srcip,
            "DESTINATION_IP": dstip,
            "PROTO":132,
            "SOURCE_MAC": srcmac,
            "DESTINATION_MAC": dstmac
            }
        )

proto.create(interface)
# Describe the Layer-3 payload - plain IPv6 header
print("[+] Parsing payload fields...")
load = bbuzz.payload.Payload()

load.add("0000000000000000000000000000000000000000000000000000000000000000",
        {                                           # sctp header
            "FORMAT": "bin",
            "TYPE": "binary",
            "LENGTH": 64,
            "FUZZABLE": True
            }
        )

#load.add('0000000000000000000000000000000000000000000000000000000000000000',                                      # sctp header
#        {
#            "FORMAT": "bin",
#            "TYPE": "binary",
#            "LENGTH": 96,
#            "FUZZABLE": True,
#            }
#        )

# Generate payload mutations
print("[+] Generating mutations...")
mutagen = bbuzz.mutate.Mutate(load, {"STATIC": True, "RANDOM": True})
#mutagen = bbuzz.mutate.Mutate(load, {"STATIC": False, "RANDOM": True})

# Sart fuzzing
print("[+] Starting fuzzing...")
fuzzer = bbuzz.fuzz.Fuzz()
fuzzer.fuzz(mutagen, proto)

