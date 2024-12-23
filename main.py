#!/bin/env python3

from os import geteuid
from json import load as load_json
from types import SimpleNamespace
from ipaddress import IPv4Address, IPv4Network
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, gethostname, gethostbyname
from binascii import hexlify

if geteuid() != 0:
	print("Error: Elevated privileges are required.")
	exit(1)

MAX_TRANSMISSION_UNIT = 1500
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
NO_IP_ADDRESS = IPv4Address("0.0.0.0")
DHCP_OP_CODES = SimpleNamespace()
DHCP_OP_CODES.REQUEST = 1
DHCP_OP_CODES.REPLY = 2
HARDWARE_TYPES = SimpleNamespace()
HARDWARE_TYPES.ETHERNET = 1
HARDWARE_LENGTHS = SimpleNamespace()
HARDWARE_LENGTHS.ETHERNET = 6
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCP_OPTIONS = SimpleNamespace()
DHCP_OPTIONS.SUBNET_MASK = 1
DHCP_OPTIONS.ROUTER = 3
DHCP_OPTIONS.DNS_SERVER_IP_ADDRESS = 6
#DHCP_OPTIONS.DOMAIN = 15
#DHCP_OPTIONS.VENDOR_SPECIFIC_INFORMATION = 43
#DHCP_OPTIONS.NETBIOS_IP_ADDRESS = 44
#DHCP_OPTIONS.NETBIOS_NODE_TYPE = 46
DHCP_OPTIONS.REQUESTED_IP_ADDRESS = 50
DHCP_OPTIONS.LEASE_TIME = 51
DHCP_OPTIONS.MESSAGE_TYPE = 53
DHCP_OPTIONS.DHCP_SERVER_IP_ADDRESS = 54
DHCP_OPTIONS.PARAMETER_REQUEST_LIST = 55
#DHCP_OPTIONS_MAX_MESSAGE_SIZE = 57
DHCP_OPTIONS.RENEWAL_TIME = 58
DHCP_OPTIONS.REBINDING_TIME = 59
#DHCP_OPIONS.VENDOR_CLASS_ID = 60
#DHCP_OPTIONS.CLIENT_ID = 61
#DHCP_OPTIONS.TFTP_SERVER_IP_ADDRESS = 66
#DHCP_OPTIONS.BOOTFILE = 67
#DHCP_OPTIONS.UNASSIGNED = 108
#DHCP_OPTIONS.CAPTIVE_PORTAL = 114
#DHCP_OPTIONS.DOMAIN_SEARCH_LIST = 119
#DHCP_OPTIONS.SIP_SERVER_IP_ADDRESS = 120
#DHCP_OPTIONS.CLASSLESS_STATIC_ROUTES = 121
#DHCP_OPTIONS.PROXY_AUTODISCOVERY = 252
DHCP_OPTIONS.END = 255
#NETBIOS_NODE_TYPES = SimpleNamespace()
#NETBIOS_NODE_TYPES.BROADCAST = 1
#NETBIOS_NODE_TYPES.PEER_TO_PEER = 2
#NETBIOS_NODE_TYPES.MIXED = 3
#NETBIOS_NODE_TYPES.HYBRID = 4
DHCP_MESSAGE_TYPES = SimpleNamespace()
DHCP_MESSAGE_TYPES.DISCOVER = 1
DHCP_MESSAGE_TYPES.OFFER = 2
DHCP_MESSAGE_TYPES.REQUEST = 3
#DHCP_MESSAGE_TYPES.DECLINE = 4
DHCP_MESSAGE_TYPES.ACK = 5
DHCP_MESSAGE_TYPES.NAK = 6
#DHCP_MESSAGE_TYPES.RELEASE = 7
#DHCP_MESSAGE_TYPES.INFORM = 8
#DHCP_MESSAGE_TYPES.LEASEQUERY = 10

config = load_json(open("./config.json", "r"))
config = SimpleNamespace(**config)
config.router = IPv4Address(config.router)
config.dhcp = IPv4Address(config.dhcp)
config.subnet_mask = IPv4Address(config.subnet_mask)
config.range = {"min": IPv4Address(config.range[0]), "max": IPv4Address(config.range[1])}
config.range = SimpleNamespace(**config.range)
if type(config.dns) == str:
	config.dns = IPv4Address(config.dns)	
elif type(config.dns) == list:
	config.dns = {"primary":IPv4Address(config.dns[0]), "secondary":IPv4Address(config.dns[1])}
	config.dns = SimpleNamespace(**config.dns)

available_ip_addresses = []
for ip_address in IPv4Network(f"{str(config.router)}/{str(config.subnet_mask)}", strict=False).hosts():
	if config.range.min <= ip_address <= config.range.max:
		available_ip_addresses.append(ip_address)

used_ip_addresses = []

server = socket(AF_INET, SOCK_DGRAM)
server.bind(("0.0.0.0", DHCP_SERVER_PORT))
server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

while True:

	client_data, client_address = server.recvfrom(MAX_TRANSMISSION_UNIT)

	client_data = {
		#"op": int(client_data[0]),
		#"htype": int(client_data[1]),
		#"hlen": int(client_data[2]),
		#"hops": int(client_data[3]),
		"xid": int.from_bytes(client_data[4:8], byteorder="big"),
		#"secs": int.from_bytes(client_data[8:10], byteorder="big"),
		#"flags": int.from_bytes(client_data[10:12], byteorder="big"),
		"ciaddr": IPv4Address(client_data[12:16]),
		#"yiaddr": IPv4Address(client_data[16:20]),
		#"siaddr": IPv4Address(client_data[20:24]),
		#"giaddr": IPv4Address(client_data[24:28]),
		"chaddr": client_data[28:44],
		#"sname": client_data[44:108].decode("utf-8").replace("\x00", ""),
		#"file": client_data[108:236].decode("utf-8").replace("\x00", ""),
		"options_data": client_data[240:]
	}
	client_data = SimpleNamespace(**client_data)
	
	client_data.options = SimpleNamespace()
	client_data.options.requested_parameters = []
	options_index = 0
	while options_index < len(client_data.options_data):

		option_code = int(client_data.options_data[options_index])
		option_length = int(client_data.options_data[options_index+1])		
		
		if option_code == DHCP_OPTIONS.END:
			options_index = len(client_data.options_data)
			continue
		
		elif option_code == DHCP_OPTIONS.MESSAGE_TYPE:
			option_value = client_data.options_data[options_index+2:options_index+2+option_length]
			option_value = int.from_bytes(option_value, byteorder="big")
			client_data.options.message_type = option_value
		
		elif option_code == DHCP_OPTIONS.REQUESTED_IP_ADDRESS:
			option_value = client_data.options_data[options_index+2:options_index+2+option_length]
			option_value = IPv4Address(option_value)
			client_data.options.requested_ip_address = option_value
		
		elif option_code == DHCP_OPTIONS.PARAMETER_REQUEST_LIST:
			option_value = client_data.options_data[options_index+2:options_index+2+option_length]
			for requested_parameter in option_value:
				client_data.options.requested_parameters.append(requested_parameter)
		
		options_index += 2 + option_length
	
	del client_data.options_data
	
	server_data = SimpleNamespace()
	server_data.op = DHCP_OP_CODES.REPLY
	server_data.htype = HARDWARE_TYPES.ETHERNET
	server_data.hlen = HARDWARE_LENGTHS.ETHERNET
	server_data.hops = 0
	server_data.xid = client_data.xid
	server_data.secs = 0
	server_data.flags = 0
	server_data.ciaddr = client_data.ciaddr
	server_data.siaddr = NO_IP_ADDRESS
	server_data.giaddr = NO_IP_ADDRESS
	server_data.chaddr = client_data.chaddr
	server_data.sname = gethostname()
	server_data.file = ""

	server_data.options = SimpleNamespace()
	server_data.options.subnet_mask = config.subnet_mask
	server_data.options.router = config.router
	server_data.options.dns = config.dns
	
	if client_data.options.message_type == DHCP_MESSAGE_TYPES.DISCOVER:
		used_ip_address = SimpleNamespace()
		used_ip_address.ip_address = available_ip_addresses[0]
		used_ip_address.hardware_address = client_data.chaddr
		used_ip_addresses.append(used_ip_address)
		available_ip_addresses = available_ip_addresses[1:]
		server_data.options.message_type = DHCP_MESSAGE_TYPES.OFFER
		server_data.yiaddr = used_ip_address.ip_address
				
	elif client_data.options.message_type == DHCP_MESSAGE_TYPES.REQUEST:
		
		ip_address_used = False
		for used_ip_address in used_ip_addresses:
			if used_ip_address.ip_address == client_data.options.requested_ip_address:
				ip_address_used = True
				if used_ip_address.hardware_address == client_data.chaddr:
					server_data.options.message_type = DHCP_MESSAGE_TYPES.ACK
					server_data.yiaddr = used_ip_address.ip_address	
				else:
					server_data.options.message_type = DHCP_MESSAGE_TYPES.NAK
					server_data.yiaddr = NO_IP_ADDRESS
	
		if not ip_address_used:
			used_ip_address = SimpleNamespace()
			used_ip_address.ip_address = client_data.options.requested_ip_address
			used_ip_address.hardware_address = client_data.chaddr
			used_ip_addresses.append(used_ip_address)
			available_ip_addresses = available_ip_addresses[1:]
			server_data.options.message_type = DHCP_MESSAGE_TYPES.ACK
			server_data.yiaddr = used_ip_address.ip_address

	server_raw_data = b""
	server_raw_data += server_data.op.to_bytes(1, byteorder="big")
	server_raw_data += server_data.htype.to_bytes(1, byteorder="big")
	server_raw_data += server_data.hlen.to_bytes(1, byteorder="big")
	server_raw_data += server_data.hops.to_bytes(1, byteorder="big")
	server_raw_data += server_data.xid.to_bytes(4, byteorder="big")
	server_raw_data += server_data.secs.to_bytes(2, byteorder="big")
	server_raw_data += server_data.flags.to_bytes(2, byteorder="big")
	server_raw_data += server_data.ciaddr.packed
	server_raw_data += server_data.yiaddr.packed
	server_raw_data += server_data.siaddr.packed
	server_raw_data += server_data.giaddr.packed
	server_raw_data += server_data.chaddr
	server_raw_data += server_data.sname.encode("utf-8").ljust(64, b"\x00")
	server_raw_data += server_data.file.encode("utf-8").ljust(128, b"\x00")
	server_raw_data += DHCP_MAGIC_COOKIE
	
	server_raw_data += DHCP_OPTIONS.MESSAGE_TYPE.to_bytes(1, byteorder="big")
	server_raw_data += (1).to_bytes(1, byteorder="big")
	server_raw_data += server_data.options.message_type.to_bytes(1, byteorder="big")
	
	server_raw_data += DHCP_OPTIONS.LEASE_TIME.to_bytes(1, byteorder="big")
	server_raw_data += (4).to_bytes(1, byteorder="big")
	server_raw_data += config.lease_time.to_bytes(4, byteorder="big")
	
	server_raw_data += DHCP_OPTIONS.RENEWAL_TIME.to_bytes(1, byteorder="big")
	server_raw_data += (4).to_bytes(1, byteorder="big")
	server_raw_data += int(config.lease_time*0.5).to_bytes(4, byteorder="big")
	
	server_raw_data += DHCP_OPTIONS.REBINDING_TIME.to_bytes(1, byteorder="big")
	server_raw_data += (4).to_bytes(1, byteorder="big")
	server_raw_data += int(config.lease_time*0.75).to_bytes(4, byteorder="big")
	
	server_raw_data += DHCP_OPTIONS.DHCP_SERVER_IP_ADDRESS.to_bytes(1, byteorder="big")
	server_raw_data += (4).to_bytes(1, byteorder="big")
	server_raw_data += config.dhcp.packed
	
	if DHCP_OPTIONS.SUBNET_MASK in client_data.options.requested_parameters:
		server_raw_data += DHCP_OPTIONS.SUBNET_MASK.to_bytes(1, byteorder="big")
		server_raw_data += (4).to_bytes(1, byteorder="big")
		server_raw_data += config.subnet_mask.packed
	
	if DHCP_OPTIONS.ROUTER in client_data.options.requested_parameters:
		server_raw_data += DHCP_OPTIONS.ROUTER.to_bytes(1, byteorder="big")
		server_raw_data += (4).to_bytes(1, byteorder="big")
		server_raw_data += config.router.packed
		
	if DHCP_OPTIONS.DNS_SERVER_IP_ADDRESS in client_data.options.requested_parameters:
		if type(config.dns) == IPv4Address:
			server_raw_data += DHCP_OPTIONS.DNS_SERVER_IP_ADDRESS.to_bytes(1, byteorder="big")
			server_raw_data += (4).to_bytes(1, byteorder="big")
			server_raw_data += config.dns.packed
		elif type(config.dns) == SimpleNamespace:
			server_raw_data += DHCP_OPTIONS.DNS_SERVER_IP_ADDRESS.to_bytes(1, byteorder="big")
			server_raw_data += (8).to_bytes(1, byteorder="big")
			server_raw_data += config.dns.primary.packed
			server_raw_data += config.dns.secondary.packed
	
	server_raw_data += DHCP_OPTIONS.END.to_bytes(1, byteorder="big")
	
	server.sendto(server_raw_data, ("255.255.255.255", DHCP_CLIENT_PORT))

