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
import sys

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
import sys

def run_checksetup():
    """
    Runs checksetup.py to verify the setup before proceeding.
    Exits the program if checksetup.py fails.
    """
    print("[+] Running checksetup.py to verify setup...")
    try:
        # Run checksetup.py located in the same directory as run_all.py
        script_dir = os.path.dirname(os.path.abspath(__file__))
        checksetup_path = os.path.join(script_dir, "checksetup.py")
        subprocess.run(f"python3 {checksetup_path}", shell=True, check=True)
        print("[+] checksetup.py completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] checksetup.py failed: {e}. Exiting program.")
        sys.exit(1)

def main():
    # Run checksetup.py before proceeding
    run_checksetup()

    # Placeholder for the rest of the script logic
    print("[+] Proceeding with the rest of the script...")

if __name__ == "__main__":
    main()
