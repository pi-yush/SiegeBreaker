from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send


def sendPing(destIP, signalString, times):
	pkt = IP(dst=destIP)/ICMP()/signalString
	for i in range(0, times):
		send(pkt)


