#!/usr/bin/python3 -tt
# coding=utf-8
#
# This file is part of Bbuzz
#
# Licensed under the MIT license (MIT)
# Please see LICENSE file for more details

import time
from time import sleep
from datetime import datetime

class Fuzz():
    """Conduct and manage the fuzzing process"""
    def __init__(self, timeout=0.1):
        """Set fuzzing parameters"""
        self.timeout = timeout

    def fuzz(self, mutant, protocol):
        """Start the fuzzing process"""
        while True:
            payload = mutant.get()
            try:
                #print("Payload hex: ", payload.hex())
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] Payload hex: {payload.hex()}")
            except:
                payload = bytes(payload[2:-1], 'utf-8')
                #print("Payload: ", payload.hex())
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] Payload hex: {payload.hex()}")
            if payload == "__END":
                continue
            elif payload == "__FIN":
                print("FIN")
                break
            elif payload:
                protocol.send(payload)
                sleep(self.timeout)
            elif not payload:
                break
        protocol.kill()

    def monitor(self):
        """Monitor the fuzzing target"""
        pass

    def track(self):
        """Track the fuzzing process"""
        pass
