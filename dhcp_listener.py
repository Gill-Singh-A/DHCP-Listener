#!/usr/bin/env python3

from os import geteuid
from sys import argv
from scapy.all import sniff, Ether, DHCP
from datetime import date
from pickle import load, dump
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime

packets, verbose = [], True

status_color = {
	'+': Fore.GREEN,
	'-': Fore.RED,
	'*': Fore.YELLOW,
	':': Fore.CYAN,
	' ': Fore.WHITE,
}

def get_time():
	return strftime("%H:%M:%S", localtime())
def display(status, data):
	print(f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}")

def get_arguments(*args):
	parser = OptionParser()
	for arg in args:
		parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
	return parser.parse_args()[0]

def check_root():
	return geteuid() == 0

def listen_dhcp(iface=None):
	if iface:
		sniff(iface=iface, prn=print_packet, filter="udp and (port 67 or port 68)")
	else:
		sniff(prn=print_packet, filter="udp and (port 67 or port 68)")

def print_packet(packet):
	mac, ip, hostname, vendor_id = [None], [None], [None], [None]
	if packet.haslayer(Ether):
		mac = packet.getlayer(Ether).src
	dhcp_options = packet[DHCP].options
	for item in dhcp_options:
		try:
			label, value = item
		except ValueError:
			continue
		if label == "requested_addr":
			ip = value
		elif label == "hostname":
			hostname = value.decode()
		elif label == "vendor_class_id":
			vendor_id = value.decode()
	if mac and ip and hostname and vendor_id:
		if verbose:
			display('+', f"{mac} - {hostname} / {vendor_id} requested {ip}")
		packets.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor_id': vendor_id})

if __name__ == "__main__":
	data = get_arguments(('-i', "--iface", "iface", "Interface on which sniffing has to be done"),
					     ('-v', "--verbose", "verbose", "Display Useful Information related to the packets on the screen (True/False)(Default = True)"),
						 ('-w', "--write", "write", "Dump the Packets to file"),
						 ('-r', "--read", "read", "Read Packets from a dump file"))
	if data.read:
		try:
			with open(data.read, 'rb') as file:
				local_packets = load(file)
		except FileNotFoundError:
			display('-', f"{Back.MAGENTA}{data.read}{Back.RESET} File not found!")
			exit(0)
		except:
			display('-', f"Error reading from file {Back.MAGENTA}{data.read}{Back.RESET}")
			exit(0)
		for packet in local_packets:
			print_packet(packet)
		exit(0)
	if data.verbose == "False":
		verbose = False
	if not check_root():
		display('-', f"This Program requires {Back.MAGENTA}root{Back.RESET} Privileges")
		exit(0)
	listen_dhcp(data.iface)
	if data.write:
		with open(data.write, 'wb') as file:
			dump(packets, file)