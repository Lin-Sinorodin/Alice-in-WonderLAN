import random
import scapy.all as scapy
from typing import Tuple


def ip_str_to_int(ip: str):
	"""Convert ip in string representation to its integer number representation."""
	ip_split = ip.split(".")
	if len(ip_split) == 4:
		a1, a2, a3, a4 = ip_split
		return (int(a1) << 24) + (int(a2) << 16) + (int(a3) << 8) + int(a4)


def ip_int_to_str(ip: int):
	"""Convert ip in int number representation to its string representation."""
	a1 = (ip & (0xff << 24)) >> 24
	a2 = (ip & (0xff << 16)) >> 16
	a3 = (ip & (0xff << 8)) >> 8
	a4 = ip & 0xff
	return ".".join([str(a1), str(a2), str(a3), str(a4)])


def get_random_ip_in_subnet(iface_ip: str, iface_subnet: int) -> str:
	"""Generate a random ip address that is valid for the given subnet."""
	base_in_sub = ip_str_to_int(iface_ip) & iface_subnet
	rand_in_sub = random.randint(1, iface_subnet ^ 0xffffffff)
	return ip_int_to_str(base_in_sub + rand_in_sub)


def get_user_int(message: str) -> int:
	"""Get an input from the user, with the given message."""
	num = input(message)
	try:
		return int(num)
	except:
		raise ValueError("not a valid number")


def get_routing_interfaces() -> Tuple[scapy.NetworkInterface, scapy.NetworkInterface]:
	"""Show interfaces to the user and get from the src  and dst interfaces."""
	scapy.show_interfaces()
	src_iface_idx = get_user_int("Enter source interface index: ")
	dst_iface_idx = get_user_int("Enter destination interface index: ")
	src_iface = scapy.dev_from_index(src_iface_idx)
	dst_iface = scapy.dev_from_index(dst_iface_idx)
	return src_iface, dst_iface
