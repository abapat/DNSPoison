import argparse
import logging
import datetime
from os import uname
from subprocess import call
from sys import argv, exit
from time import ctime, sleep
from pprint import pprint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

global interface
global file
global expression
global requests
global responses
global c


def parseArgs():
	global interface
	global hosts
	global expression
	global file
	global requests
	global responses
	global c

	c = 1
	# dnsinject [-i interface] [-r file] expression
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', metavar='interface', help='Network device to listen on')
	parser.add_argument('-r', metavar='tracefile', help='Read packets from <tracefile> (tcpdump format)')
	parser.add_argument('expression', nargs='*', help='BPF filter')
	res = parser.parse_args()

	if len(res.expression) > 1:
		print("Error: more than one expression")
		parser.print_help()
		exit(0)

	if len(res.expression) == 1:
		expression = res.expression[0]
	else:
		expression = None

	file = res.r
	interface = res.i

	requests = set()
	responses = dict()
	
def handlePkt(pkt):
	global requests
	global responses
	global c

	if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
		return

	destIP = pkt[IP].dst
	destPort = pkt[UDP].dport
	srcPort = pkt[UDP].sport

	if srcPort != 53:
		return #not DNS response

	query = pkt[DNS].qd.qname
	dnsID = pkt[DNS].id
	answer = pkt[DNS].qr
	answers = getTypeA(pkt[DNS].an, pkt[DNS].ancount)

	if len(answers) == 0:
		return
	
	#printPacket(destIP, destPort, dnsID, query, answers)

	tup = (dnsID, query)
	if tup in requests and str(answers) != str(responses[tup]):
		printWarning(tup, answers)
	else:
		requests.add(tup)
		responses[tup] = answers
	
	#print("-----------------------------------------")
	#pprint(pkt)
	#print("-----------------------------------------\n")

	c += 1	

def printPacket(destIP, destPort, dnsID, query, answers):
	print("Packet " + str(c))
	print("To %s Port %s" % (destIP, destPort))
	print("TXID: %s Query: %s" % (dnsID, query))
	print(str(len(answers)) + " Answer[s]: " + str(answers))
	print("\n")


def getTypeA(answers, size):
	ips = list()
	for i in range(0, size):
		if answers[i].type == 1:
			ips.append(answers[i].rdata)

	return ips 

def printWarning(tup, ips):
	time = getTime()
	print("[%s] DNS Poisoning Attempt" % time)
	print("TXID %s Query %s" % tup)
	print("Answer 1: " + str(responses[tup]))
	print("Answer 2: " + str(ips))
	print("\n")

def getTime():
	t = time.time()
	ts = datetime.datetime.fromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S')
	return ts

def main():
	parseArgs()
	
	if interface != None:
		dnsPacket = sniff(iface=interface, prn = handlePkt)
	elif file != None:
		 dnsPacket = sniff(offline=file, prn = handlePkt)
	else:
		dnsPacket = sniff(prn = handlePkt)
		#sleep(1)


if __name__ == '__main__':
    main()

#sniff(filter = "port 53", prn = querysniff, store = 0)
#print "\n[*] Shutting Down..."
