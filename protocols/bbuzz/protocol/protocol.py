#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import bbuzz.common

import socket
from binascii import unhexlify
import socket
import fcntl
import struct

def get_interface_index(interface_name):
    SIOCGIFINDEX = 0x8933  # IOCTL to get the interface index
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', interface_name[:15].encode('utf-8'))
    try:
        res = fcntl.ioctl(sock.fileno(), SIOCGIFINDEX, ifreq)
        index = struct.unpack('I', res[16:20])[0]
        return index
    except IOError as e:
        raise ValueError(f"Interface {interface_name} not found: {e}")

class Protocol():
    def __init__(self, protocol_layer, protocol_options):
        """
        Select the communication protocol, provide communication options
        to establish the connectivity and deliver the fuzzing test cases.

        Protocol class accepts the following options:
        protocol_layer: Initial layer to be used for connection establishment.
                        Accepts values of 'raw2', 'raw3' or 'raw4'.
        protocol_options:   Specifies the required options, based on the layer
                        chosen.
                        For 'raw2' a dictionary of the following values
                        is expected to form a Layer-2 frame:
                        "SOURCE_MAC": "STR_MAC_ADDRESS"
                        "DESTINATION_MAC": "STR_MAC_ADDRESS"
                        "ETHER_TYPE": "STR_0xETHER_TYPE"
                        NOTE: ETHER_TYPE field can be also used to represent
                        .1Q VLAN tagging information together with the
                        ETHER_TYPE.

                        For 'raw3' a dictionary of string values
                        is expected to form a Layer-3 packet:
                        "SOURCE_IP": "STR_IP_ADDRESS"
                        "DESTINATION_IP": "STR_IP_ADDRESS"
                        "IP_VERSION": INT_IP_VERSION

                        For 'raw4' a dictionary of the follwoing values
                        ((DESTINATION_IP, DESTINATION_PORT), PROTO)
                        is expected to form a a Layer-4 packet/datagram:
                        "DESTINATION_IP": "STR_IP_ADDRESS"
                        "SOURCE_IP": "STR_IP_ADDRESS"
                        "IP_VERSION": INT_IP_VERSION
                        "PROTO": INT_0xPROTO_NUMBER (e.g., UDP=0x11, TCP=0x06)
                        "DESTINATION_PORT": INT_PORT_NUMBER
                        "SOURCE_PORT": INT_PORT_NUMBER
                        "BROADCAST": BOOL_TURE-FALSE

        """
        self.layer = protocol_layer.lower()
        self.options = protocol_options
        self.sock = False
        self.interface = ""

    def create(self, interface="enp216s0f1", l4proto = "IPPROTO_SCTP"):
        """Establish a specific layer connection"""
        self.interface = interface 
        if not self.sock:
            if self.layer == 'raw1':
                self.sock = socket.socket(
                        socket.AF_PACKET,
                        socket.SOCK_RAW#,
                        #socket.htons(int(self.options["ETHER_TYPE"], 16))
                        )
                self.sock.bind((interface, 0))
                return self.sock

            if self.layer == 'raw2':
                self.sock = socket.socket(
                        socket.AF_PACKET,
                        socket.SOCK_RAW,
                        socket.htons(int(self.options["ETHER_TYPE"], 16))
                        )
                self.sock.bind((interface, 0))
                return self.sock

            if self.layer == 'raw3':
                if self.options["IP_VERSION"] == 4:
                    INET = 2
                    addr = "0.0.0.0" 
                    self.sock = socket.socket(
                          INET,
                          socket.SOCK_RAW,l4proto
                          )
                    self.sock.bind((addr, 0))

                elif self.options["IP_VERSION"] == 6:
                    INET = 10
                    addr = "::" 
                    self.sock = socket.socket(
                        INET,
                        socket.SOCK_RAW,l4proto
                        )
                    self.sock.bind((addr, 0,0,0))
                return self.sock

            if self.layer == 'raw4':
                ip_version = self.options["IP_VERSION"]
                if ip_version == 4:
                    INET = 2
                elif ip_version == 6:
                    INET = 10
                PROTO = self.options["PROTO"]
                self.sock = socket.socket(
                        INET,
                        PROTO
                        )
                socket.SO_BINDTODEVICE = 25
                self.sock.setsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_BINDTODEVICE,
                        interface.encode()
                        )
                # Configure BROADCAST interface
                if self.options["BROADCAST"]:
                    self.sock.setsockopt(
                            socket.SOL_SOCKET,
                            socket.SO_REUSEADDR,
                            1
                            )
                    self.sock.setsockopt(
                            socket.SOL_SOCKET,
                            socket.SO_BROADCAST,
                            1
                            )
                    return self.sock
                else:
                    self.sock.connect(
                            (
                                self.options["DESTINATION_IP"],
                                self.options["DESTINATION_PORT"]
                                )
                            )
                return self.sock

        else:
            return self.sock

    def send(self, data):
        """Send data over established connection"""

        if self.layer == 'raw1':
            print("Sending Raw pkt")
            src_mac = bbuzz.common.mac2hex(self.options["SOURCE_MAC"])
            dst_mac = bbuzz.common.mac2hex(self.options["DESTINATION_MAC"])
            #self.sock.send(dst_mac + src_mac + ethertype + data)
            #print("sending: ", str(dst_mac)+"**"+str(src_mac)+"**"+str(data)+"len: "+str(len(data)))
            self.sock.send(dst_mac + src_mac + data)


        if self.layer == 'raw2':
            src_mac = bbuzz.common.mac2hex(self.options["SOURCE_MAC"])
            dst_mac = bbuzz.common.mac2hex(self.options["DESTINATION_MAC"])
	    #jagdbg: addressing issues with unhexlify for even/odd errors
            org_ethertype = self.options["ETHER_TYPE"][2::]
            #print("original ether type = ", org_ethertype, len(org_ethertype)) 
            if len(org_ethertype) %2 != 0:
            	org_ethertype = "0" + org_ethertype
            #print("original ether type after fixing = ", org_ethertype, len(org_ethertype)) 
            ethertype = unhexlify(org_ethertype)
            #ethertype = unhexlify(self.options["ETHER_TYPE"][2::])
            #print("ether type = ", ethertype)
            self.sock.send(dst_mac + src_mac + ethertype + data)

        if self.layer == 'raw3':
            if self.options["IP_VERSION"] == 4:
                self.sock.connect((self.options["DESTINATION_IP"],0))
                try:
                	self.sock.send(data)
                except:
                	print("failed to send payload", data)
            if self.options["IP_VERSION"] == 6:
                #get the ipv6 interface index and popuate here "ip -6 addr show"
                ipv6_int_index = get_interface_index(self.interface)
                self.sock.connect((self.options["DESTINATION_IP"],0,0,ipv6_int_index))
                self.sock.send(data)

        if self.layer == 'raw4':
            if self.options["BROADCAST"]:
                self.sock.sendto(
                        data,
                        (
                            self.options["DESTINATION_IP"],
                            self.options["DESTINATION_PORT"]
                            )
                        )
            else:
                self.sock.send(data)

    def kill(self):
        """Close an established connection socket"""
        self.sock.close()
