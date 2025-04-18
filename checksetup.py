#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import os
import json
import subprocess
import sys

# Add the protocols directory to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
protocols_dir = os.path.join(script_dir, "protocols")
sys.path.append(protocols_dir)

# Import bbuzz from the protocols directory
try:
    import bbuzz
except ImportError as e:
    print(f"[!] Failed to import bbuzz from protocols directory: {e}")
    sys.exit(1)

# Load configuration from config.json
with open('config.json', 'r') as file:
    config = json.load(file)

def check_interface_exists(interface):
    """
    Checks if the interface exists.
    """
    try:
        interfaces = os.listdir('/sys/class/net/')
        if interface not in interfaces:
            print(f"[!] Interface {interface} does not exist. Exiting program.")
            sys.exit(1)
        else:
            print(f"[+] Interface {interface} exists.")
    except Exception as e:
        print(f"[!] Error checking interface existence: {e}")
        sys.exit(1)

def check_interface_link_up(interface):
    """
    Checks if the interface link is up. If not, brings it up.
    """
    try:
        with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
            operstate = f.read().strip()
        if operstate != 'up':
            print(f"[-] Interface {interface} is down. Bringing it up...")
            subprocess.run(f"sudo ip link set dev {interface} up", shell=True, check=True)
        else:
            print(f"[+] Interface {interface} is up.")
    except Exception as e:
        print(f"[!] Error checking/bringing up interface: {e}")
        sys.exit(1)

def check_ping_ipv4(dst_ip4, interface):
    """
    Checks if the destination IPv4 address is reachable via ping using the specified interface.
    """
    print(f"[+] Pinging IPv4 address: {dst_ip4} using interface: {interface}")
    try:
        subprocess.run(f"ping -I {interface} -c 3 {dst_ip4}", shell=True, check=True)
        print(f"[+] Successfully pinged IPv4 address {dst_ip4} using interface {interface}.")
    except subprocess.CalledProcessError:
        print(f"[!] Failed to ping IPv4 address {dst_ip4} using interface {interface}. Exiting program.")
        sys.exit(1)

def check_ping_ipv6(dst_ip6, interface):
    """
    Checks if the destination IPv6 address is reachable via ping using the specified interface.
    """
    print(f"[+] Pinging IPv6 address: {dst_ip6} using interface: {interface}")
    try:
        subprocess.run(f"ping6 -I {interface} -c 3 {dst_ip6}", shell=True, check=True)
        print(f"[+] Successfully pinged IPv6 address {dst_ip6} using interface {interface}.")
    except subprocess.CalledProcessError:
        print(f"[!] Failed to ping IPv6 address {dst_ip6} using interface {interface}. Exiting program.")
        sys.exit(1)

def check_and_assign_interface(interface, src_mac, src_ip4, src_ip6):
    """
    Checks if the interface has the correct MAC, IPv4, and IPv6 addresses assigned.
    If not, assigns them.
    """
    print(f"[+] Checking interface: {interface}")

    # Check current MAC address
    try:
        current_mac = subprocess.check_output(
            f"cat /sys/class/net/{interface}/address", shell=True
        ).decode().strip()
        if current_mac.lower() != src_mac.lower():
            print(f"[-] MAC address mismatch. Assigning MAC address {src_mac}...")
            subprocess.run(f"sudo ip link set dev {interface} address {src_mac}", shell=True, check=True)
        else:
            print(f"[+] MAC address is correctly set to {src_mac}.")
    except Exception as e:
        print(f"[!] Error checking/assigning MAC address: {e}")

    # Check current IPv4 address
    try:
        ipv4_output = subprocess.check_output(
            f"ip -4 addr show {interface}", shell=True
        ).decode()
        if src_ip4 not in ipv4_output:
            print(f"[-] IPv4 address mismatch. Assigning IPv4 address {src_ip4}...")
            subprocess.run(f"sudo ip addr add {src_ip4}/24 dev {interface}", shell=True, check=True)
        else:
            print(f"[+] IPv4 address is correctly set to {src_ip4}.")
    except Exception as e:
        print(f"[!] Error checking/assigning IPv4 address: {e}")

    # Check current IPv6 address
    try:
        ipv6_output = subprocess.check_output(
            f"ip -6 addr show {interface}", shell=True
        ).decode()
        if src_ip6 not in ipv6_output:
            print(f"[-] IPv6 address mismatch. Assigning IPv6 address {src_ip6}...")
            subprocess.run(f"sudo ip addr add {src_ip6}/64 dev {interface}", shell=True, check=True)
        else:
            print(f"[+] IPv6 address is correctly set to {src_ip6}.")
    except Exception as e:
        print(f"[!] Error checking/assigning IPv6 address: {e}")

# Run the checks
check_interface_exists(config["interface"])
check_interface_link_up(config["interface"])
check_and_assign_interface(
    config["interface"],
    config["srcmac"],
    config["srcip4"],
    config["srcip6"]
)
check_ping_ipv4(config["dstip4"], config["interface"])
check_ping_ipv6(config["dstip6"], config["interface"])

print("[+] Setup check completed.")
