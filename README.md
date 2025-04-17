To use:

step1: populate config.json with correct src/dst mac and ipv4/ipv6 addresses 
eg -
  "interface": "enp134s0f1",
  "dstmac": "00:00:00:00:01:01",
  "srcmac": "00:00:00:00:04:01",
  "srcip4": "13.1.1.12",
  "dstip4": "13.1.1.11",
  "srcip6": "fe80::13:1:1:12",
  "dstip6": "fe80::13:1:1:11",
	 

step2: Run the python files



TODO:
1. Add a serpate presetup script to check if the setup is ready for testing
Optional:
2. Add heartbeat test and also if it fails - ./check_setup.py  
3. Add option to delay packets sent
4. Option to stop if heartbeat fails 


References:
# Bbuz  a bit-aware network protocol fuzzing and reverse engineering framework
https://github.com/lockout/lockout.github.io/blob/master/pubs/2017-bbuzz.pdf

This Framework enables to fuzz protocol header fields and also pass raw fuzz data part of payload 


