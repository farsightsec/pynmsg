#!/usr/bin/env python 

# Written by Eric Ziegast
# nxdomain.py - look at ch202 dnsqr data from a file and print out any 
# qname / type / rcode for data that's not rcode 0 ("NOERROR"). 
# Forgive awkward key processing. Sometimes an rcode or qtype key 
# doesn't exist and would cause the script to break if accessed them.


import nmsg
import wdns
import sys

def main(fname):
	i = nmsg.input.open_file(fname)
	while True:
		m = i.read() 
		if not m:
			break
		rcode = 0
		qname = qtype = 0
		for key in m.keys():
			if key == 'rcode':
				rcode = m[key] 
				continue
			if key == 'qname':
				qname = m[key]
				continue
			if key == 'qtype':
				qtype = m[key]
				continue
			if rcode != 0 and qname != 0 and qtype != 0:
				print('%s %s %s' % (wdns.rcode_to_str(rcode),
				wdns.rrtype_to_str(qtype), wdns.domain_to_str(qname)))

if __name__ == '__main__':
	main(sys.argv[1])
