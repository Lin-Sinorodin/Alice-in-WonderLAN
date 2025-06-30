import scapy.all as scapy

DUMMY_MAC = "aa:aa:aa:aa:aa:aa"


def get_user_int(message: str) -> int:
	"""Get an input from the user, with the given message."""
	num = input(message)
	try:
		return int(num)
	except:
		raise ValueError("not a valid number")


def redirect_packet(packet: scapy.Ether, iface: scapy.NetworkInterface) -> None:
	"""Redirect the given packet to the given interface, only if it has layer3 payload."""
	if packet.haslayer(scapy.IP):
		new_ether = scapy.Ether(src=iface.mac, dst=DUMMY_MAC)
		scapy.sendp(new_ether / packet.payload, iface=iface.name)


def redirect_all(src_iface: str, dst_iface: str) -> None:
	"""Redirect all packets on src_iface to dst_iface."""
	scapy.sniff(iface=src_iface.name, prn=lambda p: redirect_packet(p, dst_iface))


if __name__ == "__main__":
	scapy.show_interfaces()

	src_iface_idx = get_user_int("Enter source interface index: ")
	dst_iface_idx = get_user_int("Enter destination interface index: ")
	src_iface = scapy.dev_from_index(src_iface_idx)
	dst_iface = scapy.dev_from_index(dst_iface_idx)
	print(f"Redirecting from {src_iface.name} to {dst_iface.name}")

	redirect_all(src_iface, dst_iface)

