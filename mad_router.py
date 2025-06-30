import random
import scapy.all as scapy
from collections import namedtuple
from utils import get_routing_interfaces, get_random_ip_in_subnet

DUMMY_MAC = "aa:aa:aa:aa:aa:aa"
NAT_MIN_PORT = 1024
NAT_MAX_PORT = 65535


NATEntry = namedtuple("NATEntry", ["in_src_ip", "in_src_port", "out_src_ip", "out_src_port", "dst_ip", "dst_port"])


class Router:
	def __init__(self, src_iface: scapy.NetworkInterface, dst_iface: scapy.NetworkInterface):
		self.src_iface = src_iface  # inside  the NAT
		self.dst_iface = dst_iface  # outside the NAT
		self.nat_table = []

	@property
	def nat_taken_ports(self):
		"""Return a list of the ports that are already taken by the nat."""
		return [entry.out_src_port for entry in self.nat_table]

	def get_nat_port(self):
		"""Get a random port that is not taken by the nat, to be used for a new nat table entry."""
		taken_ports = self.nat_taken_ports
		port = random.randint(NAT_MIN_PORT, NAT_MAX_PORT)
		while port in taken_ports:
			port = random.randint(NAT_MIN_PORT, NAT_MAX_PORT)
		return port

	def redirect_packet(self, packet: scapy.Ether) -> None:
		"""Redirect the given packet to the dst interface, only if it has layer3 payload."""
		if not packet.haslayer(scapy.IP):
			return

		layer3 = packet.payload
		if not hasattr(layer3, 'sport'):
			return

		# update the source mac in layer 2 to the mac of the output interface
		new_ether = scapy.Ether(src=self.dst_iface.mac, dst=DUMMY_MAC)

		# generate NAT entry for the packet
		nat_entry = NATEntry(
			in_src_ip=layer3.src,
			in_src_port=layer3.sport,
			out_src_ip=self.dst_iface.ip,
			out_src_port=self.get_nat_port(),
			dst_ip=layer3.dst,
			dst_port=layer3.dport
		)

		# update packet with NAT data, and save entry in the NAT table
		layer3.src = nat_entry.out_src_ip
		layer3.sport = nat_entry.out_src_port
		self.nat_table.append(nat_entry)

		# send the modified packet to the output interface
		scapy.sendp(new_ether / layer3, iface=self.dst_iface.name)

	def redirect_all(self) -> None:
		"""Redirect all packets on src_iface to dst_iface."""
		scapy.sniff(iface=self.src_iface.name, prn=lambda p: self.redirect_packet(p))


if __name__ == "__main__":
	src_iface, dst_iface = get_routing_interfaces()
	router = Router(src_iface, dst_iface)
	router.redirect_all()

