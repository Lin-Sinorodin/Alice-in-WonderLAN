import scapy.all as scapy
from utils import get_routing_interfaces

DUMMY_MAC = "aa:aa:aa:aa:aa:aa"


def redirect_packet(packet: scapy.Ether, iface: scapy.NetworkInterface) -> None:
	"""Redirect the given packet to the given interface, only if it has layer3 payload."""
	if packet.haslayer(scapy.IP):
		new_ether = scapy.Ether(src=iface.mac, dst=DUMMY_MAC)
		scapy.sendp(new_ether / packet.payload, iface=iface.name)


def redirect_all(src_iface: str, dst_iface: str) -> None:
	"""Redirect all packets on src_iface to dst_iface."""
	scapy.sniff(iface=src_iface.name, prn=lambda p: redirect_packet(p, dst_iface))


if __name__ == "__main__":
	src_iface, dst_iface = get_routing_interfaces()
	redirect_all(src_iface, dst_iface)

