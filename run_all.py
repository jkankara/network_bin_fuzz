#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz

import os
import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import sys
import time
import threading
import json

# Global flags for monitoring
_monitoring_stop_flag = threading.Event()
_connection_lost = threading.Event()

def monitor_connectivity(config, check_interval=5):
    """
    Monitors IPv4 and IPv6 connectivity in a separate thread.
    Sets the _connection_lost flag when either connection is lost.
    
    Args:
        config: Configuration dictionary containing dstip4, dstip6, and interface
        check_interval: Interval in seconds between ping checks (default: 5 seconds)
    """
    interface = config.get("interface", "eth0")
    dst_ip4 = config.get("dstip4")
    dst_ip6 = config.get("dstip6")
    
    ipv4_up = True
    ipv6_up = True
    
    while not _monitoring_stop_flag.is_set():
        # Check IPv4 connectivity
        try:
            subprocess.run(
                f"ping -I {interface} -c 1 -W 2 {dst_ip4}",
                shell=True,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if not ipv4_up:
                print(f"[+] IPv4 connection to {dst_ip4} is UP")
                ipv4_up = True
                _connection_lost.clear()
        except subprocess.CalledProcessError:
            if ipv4_up:
                print(f"[!] IPv4 connection to {dst_ip4} is DOWN")
                ipv4_up = False
                _connection_lost.set()
        
        # Check IPv6 connectivity
        try:
            subprocess.run(
                f"ping6 -I {interface} -c 1 -W 2 {dst_ip6}",
                shell=True,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if not ipv6_up:
                print(f"[+] IPv6 connection to {dst_ip6} is UP")
                ipv6_up = True
                _connection_lost.clear()
        except subprocess.CalledProcessError:
            if ipv6_up:
                print(f"[!] IPv6 connection to {dst_ip6} is DOWN")
                ipv6_up = False
                _connection_lost.set()
        
        # Sleep before next check
        _monitoring_stop_flag.wait(timeout=check_interval)

def run_checksetup():
    """
    Runs checksetup.py to verify the setup before proceeding.
    Exits the program if checksetup.py fails.
    Starts a parallel thread to monitor IPv4 and IPv6 connectivity.
    """
    print("[+] Running checksetup.py to verify setup...")
    try:
        # Run checksetup.py located in the same directory as run_all.py
        script_dir = os.path.dirname(os.path.abspath(__file__))
        checksetup_path = os.path.join(script_dir, "checksetup.py")
        subprocess.run(f"python3 {checksetup_path}", shell=True, check=True)
        print("[+] checksetup.py completed successfully.")
        
        # Load config.json to get connectivity details
        config_path = os.path.join(script_dir, "config.json")
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Start the monitoring thread to watch for connectivity loss
        _monitoring_stop_flag.clear()
        _connection_lost.clear()
        monitor_thread = threading.Thread(target=monitor_connectivity, args=(config,), daemon=True)
        monitor_thread.start()
        print("[+] Started monitoring IPv4 and IPv6 connectivity in background thread.")
        
    except subprocess.CalledProcessError as e:
        print(f"[!] checksetup.py failed: {e}. Exiting program.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error during setup: {e}. Exiting program.")
        sys.exit(1)


def run_script(script_path, timeout):
    """
    Runs a single Python script with a timeout.
    Monitors connection loss and terminates the script if connection is lost.
    """
    # Check if connection is already lost
    if _connection_lost.is_set():
        print(f"[!] Connection lost. Skipping: {script_path}")
        return
    
    try:
        print(f"[+] Running: {script_path}")
        # Use Popen to allow monitoring during execution
        process = subprocess.Popen(
            f"python3 {script_path}",
            shell=True
        )
        
        # Monitor the process and check for connection loss
        start_time = time.time()
        while True:
            # Check if connection is lost
            if _connection_lost.is_set():
                print(f"[!] Connection lost. Terminating: {script_path}")
                process.terminate()
                try:
                    process.wait(timeout=5)  # Give it 5 seconds to terminate gracefully
                except subprocess.TimeoutExpired:
                    process.kill()  # Force kill if it doesn't terminate
                return
            
            # Check if process has completed
            if process.poll() is not None:
                # Process finished
                if process.returncode == 0:
                    print(f"[+] Completed: {script_path}")
                else:
                    print(f"[!] Error: {script_path} exited with code {process.returncode}")
                return
            
            # Check for timeout
            if time.time() - start_time > timeout:
                print(f"[!] Timeout reached for: {script_path}. Terminating.")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                return
            
            # Sleep briefly to avoid busy waiting
            time.sleep(0.5)
            
    except Exception as e:
        print(f"[!] Unexpected error for {script_path}: {e}")



def run_scripts_in_protocols(mode, timeout):
    """
    Runs all Python scripts in the protocols directory.
    Supports serial and parallel execution modes.
    Stops execution if connection is lost.
    """
    # Get the protocols directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    protocols_dir = os.path.join(script_dir, "protocols")

    # Find all .py scripts in the protocols directory
    scripts = [os.path.join(protocols_dir, f) for f in os.listdir(protocols_dir) if f.endswith(".py")]

    if not scripts:
        print("[!] No Python scripts found in the protocols directory.")
        return

    print(f"[+] Found {len(scripts)} scripts in the protocols directory.")

    if mode == "serial":
        print("[+] Running scripts in serial mode...")
        for script in scripts:
            # Check if connection is lost before running each script
            if _connection_lost.is_set():
                print("[!] Connection lost. Stopping fuzzing.")
                _monitoring_stop_flag.set()
                break
            run_script(script, timeout)
    elif mode == "parallel":
        print("[+] Running scripts in parallel mode...")
        with ThreadPoolExecutor() as executor:
            futures = {executor.submit(run_script, script, timeout): script for script in scripts}
            for future in as_completed(futures):
                # Check if connection is lost
                if _connection_lost.is_set():
                    print("[!] Connection lost. Stopping fuzzing.")
                    _monitoring_stop_flag.set()
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break
                    
                script = futures[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[!] Error running {script}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Run all protocol scripts in serial or parallel.")
    parser.add_argument("--mode", choices=["serial", "parallel"], default="serial", help="Execution mode: serial or parallel")
    parser.add_argument("--timeout", type=int, default=60, help="Time limit for each script (in seconds)")
    args = parser.parse_args()

    # Run checksetup.py before proceeding
    run_checksetup()

    # Run scripts in the protocols directory
    run_scripts_in_protocols(args.mode, args.timeout)
    
    # Stop the monitoring thread
    _monitoring_stop_flag.set()
    
    # Check if fuzzing was stopped due to connection loss
    if _connection_lost.is_set():
        print("[!] Fuzzing stopped: Connection was lost.")
    else:
        print("[+] Fuzzing completed successfully.")

if __name__ == "__main__":
    main()

