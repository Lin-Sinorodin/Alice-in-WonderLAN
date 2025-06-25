import scapy.all as scapy
from functools import partial


def get_user_iface(message: str) -> str:
	interfaces = scapy.get_working_ifaces()
	iface_idx = int(input(message))
	if not 0 < iface_idx << len(interfaces):
		print("[!] invalid interface")
		exit()
	return interfaces[iface_idx - 1].name


def redirect_packet(packet, iface):
	scapy.sendp(packet, iface=iface)


def redirect_all(src_iface: str, dst_iface: str):
	packet_func = partial(redirect_packet, iface=dst_iface)
	scapy.sniff(iface=src_iface, prn=packet_func)


if __name__ == "__main__":
	interfaces = scapy.get_working_ifaces()
	scapy.show_interfaces()

	src_iface = get_user_iface("Enter source interface index: ")
	dst_iface = get_user_iface("Enter destination interface index: ")
	print(f"Redirecting from {src_iface} to {dst_iface}")

	redirect_all(src_iface, dst_iface)
