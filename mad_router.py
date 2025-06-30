import scapy.all as scapy
from utils import get_routing_interfaces, get_random_ip_in_subnet

DUMMY_MAC = "aa:aa:aa:aa:aa:aa"


class Router:
	def __init__(self, src_iface: scapy.NetworkInterface, dst_iface: scapy.NetworkInterface):
		self.src_iface = src_iface
		self.dst_iface = dst_iface
		self.proxy_ip_src_to_dst = {}
		self.proxy_ip_dst_to_src = {}
		self.route_to_subnet = {(route[3], route[4]): route[1] for route in scapy.conf.route.routes}

	def get_source_proxy_ip(self, src_ip: str) -> str:
		# generate new random proxy src ip if not generated yet
		if src_ip not in self.proxy_ip_src_to_dst:
			iface_name, iface_ip, _ = scapy.conf.route.route(src_ip)
			iface_subnet = self.route_to_subnet.get((iface_name, iface_ip))

			rand_addr = src_ip
			while (rand_addr != src_ip) and (rand_addr not in self.proxy_ip_dst_to_src) and (rand_addr != iface_ip):
				rand_addr = get_random_ip_in_subnet(iface_ip, iface_subnet)

			self.proxy_ip_src_to_dst[src_ip] = rand_addr
			self.proxy_ip_dst_to_src[rand_addr] = src_ip

		return self.proxy_ip_src_to_dst[src_ip]

	def redirect_packet(self, packet: scapy.Ether) -> None:
		"""Redirect the given packet to the dst interface, only if it has layer3 payload."""
		if not packet.haslayer(scapy.IP):
			return
		
		# update the source mac in layer 2 to the mac of the output interface
		new_ether = scapy.Ether(src=self.dst_iface.mac, dst=DUMMY_MAC)

		# update the source ip in layer 3 to the proxy ip address
		layer3 = packet.payload
		layer3.src = self.get_source_proxy_ip(layer3.src)

		# send the modified packet to the output interface
		scapy.sendp(new_ether / layer3, iface=self.dst_iface.name)

	def redirect_all(self) -> None:
		"""Redirect all packets on src_iface to dst_iface."""
		scapy.sniff(iface=self.src_iface.name, prn=lambda p: self.redirect_packet(p))


if __name__ == "__main__":
	src_iface, dst_iface = get_routing_interfaces()
	router = Router(src_iface, dst_iface)
	router.redirect_all()

