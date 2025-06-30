import scapy.all as scapy
from typing import Tuple


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
