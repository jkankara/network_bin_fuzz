#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#

import os
import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import time

# Define a timeout exception
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException

# Function to run a single script
def run_script(script_path, timeout):
    try:
        print(f"[+] Running: {script_path}")
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        subprocess.run(f"python3 {script_path}", shell=True, check=True)
        signal.alarm(0)  # Disable the alarm
        print(f"[+] Completed: {script_path}")
    except TimeoutException:
        print(f"[!] Timeout reached for: {script_path}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running {script_path}: {e}")
    except Exception as e:
        print(f"[!] Unexpected error for {script_path}: {e}")

# Function to run scripts serially
def run_serial(scripts, timeout):
    for script in scripts:
        run_script(script, timeout)

# Function to run scripts in parallel
def run_parallel(scripts, timeout):
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(run_script, script, timeout): script for script in scripts}
        for future in as_completed(futures):
            script = futures[future]
            try:
                future.result()
            except Exception as e:
                print(f"[!] Error running {script}: {e}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Run all protocol scripts in serial or parallel.")
    parser.add_argument("--mode", choices=["serial", "parallel"], default="serial", help="Execution mode: serial or parallel")
    parser.add_argument("--timeout", type=int, default=60, help="Time limit for each script (in seconds)")
    args = parser.parse_args()

    # Get all Python scripts in the protocols directory
    protocols_dir = os.path.join(os.getcwd(), "protocols")
    scripts = [os.path.join(protocols_dir, f) for f in os.listdir(protocols_dir) if f.endswith(".py")]

    print(f"[+] Found {len(scripts)} scripts in {protocols_dir}")

    # Run scripts based on the selected mode
    if args.mode == "serial":
        print("[+] Running scripts in serial mode...")
        run_serial(scripts, args.timeout)
    elif args.mode == "parallel":
        print("[+] Running scripts in parallel mode...")
        run_parallel(scripts, args.timeout)

    print("[+] All scripts executed.")

if __name__ == "__main__":
    main()
