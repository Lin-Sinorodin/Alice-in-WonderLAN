import scapy.all as scapy
from utils import get_routing_interfaces

DUMMY_MAC = "aa:aa:aa:aa:aa:aa"

class Router:
	def __init__(self, src_iface: scapy.NetworkInterface, dst_iface: scapy.NetworkInterface):
		self.src_iface = src_iface
		self.dst_iface = dst_iface

	def redirect_packet(self, packet: scapy.Ether) -> None:
		"""Redirect the given packet to the dst interface, only if it has layer3 payload."""
		if packet.haslayer(scapy.IP):
			new_ether = scapy.Ether(src=self.dst_iface.mac, dst=DUMMY_MAC)
			scapy.sendp(new_ether / packet.payload, iface=self.dst_iface.name)
	
	def redirect_all(self) -> None:
		"""Redirect all packets on src_iface to dst_iface."""
		scapy.sniff(iface=self.src_iface.name, prn=lambda p: self.redirect_packet(p))


if __name__ == "__main__":
	src_iface, dst_iface = get_routing_interfaces()
	router = Router(src_iface, dst_iface)
	router.redirect_all()

