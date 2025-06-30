import random
import threading
import scapy.all as scapy
from collections import namedtuple
from utils import get_routing_interfaces, get_random_ip_in_subnet

DUMMY_MAC = "aa:aa:aa:aa:aa:aa"
NAT_MIN_PORT = 1024
NAT_MAX_PORT = 65535
FIREWALL_UDP_BLOCK = 12345


NATEntry = namedtuple("NATEntry", ["in_src_ip", "in_src_port", "out_src_ip", "out_src_port", "dst_ip", "dst_port"])


class Router:
	def __init__(self, src_iface: scapy.NetworkInterface, dst_iface: scapy.NetworkInterface):
		self.src_iface = src_iface  # inside  the NAT
		self.dst_iface = dst_iface  # outside the NAT
		self.nat_table = []
		self.lock = threading.Lock()

		self.in_to_out_sniffer = scapy.AsyncSniffer(iface=self.src_iface.name, prn=self.redirect_out)
		self.out_to_in_sniffer = scapy.AsyncSniffer(iface=self.dst_iface.name, prn=self.redirect_in)

	def __enter__(self):
		self.start()
		return self

	def __exit__(self, exc_type, exc_value, exc_tb):
		self.stop()

	def start(self):
		"""Start redirectiong in both directions, with async sniffers."""
		self.in_to_out_sniffer.start()
		self.out_to_in_sniffer.start()

	def stop(self):
		"""Stop redirectiong in both directions."""
		self.in_to_out_sniffer.stop()
		self.out_to_in_sniffer.stop()

	@property
	def nat_taken_ports(self):
		"""Return a list of the ports that are already taken by the nat."""
		with self .lock:
			return [entry.out_src_port for entry in self.nat_table]

	def get_nat_port(self):
		"""Get a random port that is not taken by the nat, to be used for a new nat table entry."""
		taken_ports = self.nat_taken_ports()
		port = random.randint(NAT_MIN_PORT, NAT_MAX_PORT)
		while port in taken_ports:
			port = random.randint(NAT_MIN_PORT, NAT_MAX_PORT)
		return port

	def redirect_out(self, packet: scapy.Ether) -> None:
		"""Redirect the given packet to the dst interface, apply nat translation."""
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
		with self.lock:
			self.nat_table.append(nat_entry)

		# send the modified packet to the output interface
		scapy.sendp(new_ether / layer3, iface=self.dst_iface.name)

	def redirect_in(self, packet: scapy.Ether) -> None:
		"""Redirect the given packet to the src interface, apply firewall rulse and nat translation."""
		if not packet.haslayer(scapy.IP):
			return

		layer3 = packet.payload
		if not hasattr(layer3, 'sport'):
			return
		
		# apply firewall - block UDP on port 12345
		if packet.haslayer(scapy.UDP) and layer3.dport == FIREWALL_UDP_BLOCK:
			return
		
		# resolve NAT address
		for i, entry in enumerate(self.nat_table):
			src_match = (layer3.src == entry.dst_ip) and (layer3.sport == entry.dst_port)
			dst_match = (layer3.dst == entry.out_src_ip) and (layer3.dport == entry.out_src_port)
			if src_match and dst_match:
				layer3.dst = entry.in_src_ip
				layer3.dport = entry.in_src_port
				with self.lock:
					del self.nat_table[i]

				break

		# update the source mac in layer 2 to the mac of the input interface
		new_ether = scapy.Ether(src=self.src_iface.mac, dst=DUMMY_MAC)

		# send the modified packet to the input interface
		scapy.sendp(new_ether / layer3, iface=self.src_iface.name)


if __name__ == "__main__":
	src_iface, dst_iface = get_routing_interfaces()
	with Router(src_iface, dst_iface) as router:
		print(f"Redirecting, src (inside NAT) at {src_iface.name}, dst (outside NAT) at {dst_iface.name}")
