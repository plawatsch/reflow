import pytun
from pytun import TunTapDevice
from dpkt.ip import IP 
import dpkt
import socket
import pickle
import dnet

tun = TunTapDevice(name='tunnelator', flags = pytun.IFF_NO_PI | pytun.IFF_TUN)

tun.addr = '10.8.0.2'
tun.dstaddr = '10.8.0.1'
tun.netmask = '255.255.0.0'
tun.mtu = 1500
tun.persist(True)

tun.up()


# maps (src, dst) -> real target

# maps (src_ip, src_p, dst_ip, dst_p) -> (src_ip, src_p, dst_ip, dst_p)
flow_rules = {}

def get_host_mapping(src_addr, src_port, dst_addr, dst_port):
	try:		
		connection = (src_addr, src_port, dst_addr, dst_port)
		if connection in flow_rules:
			return flow_rules[connection]

		m = {}
		m["request"]="getflowrule"
		m["src_address"] = src_addr
		m["src_port"] = src_port
		m["dst_address"] = dst_addr
		m["dst_port"] = dst_port

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		s.connect(('127.0.0.1', 13373))
		s.send(pickle.dumps(m))
		result = pickle.loads(s.recv(1024))
		s.close()
		if result["result"] == "ok":
			flow_rules[result["forward"][0]] = result["forward"][1]
			flow_rules[result["backward"][0]] = result["backward"][1]			
		  	return result["forward"][1]

		print("Failed to get mapping for " + src_addr + " to " + dst_addr)
		return None
	except Exception as e:
		print("Exception caught when trying to lookup address.... " + `e`)

	return None

while (True):
	d = tun.read(tun.mtu)
	p = IP(d)

	src_a = dnet.ip_ntoa(p.src)
	dst_a = dnet.ip_ntoa(p.dst)

	src_p = -1
	dst_p = -1

	has_port = False
	if (p.p == dpkt.ip.IP_PROTO_TCP) or (p.p == dpkt.ip.IP_PROTO_UDP):
		has_port = True
		src_p = `p.data.sport`
		dst_p = `p.data.dport`

	# drop ssdp spam
	if dst_a == "239.255.255.250":
		continue

	# drop mdns spam
	if dst_a == "224.0.0.251":
		continue

	# drop igmp
	if dst_a == "224.0.0.22":
		continue

	mapping = get_host_mapping(src_a, src_p, dst_a, dst_p)
	if mapping != None:
	
		p.src = dnet.ip_aton(mapping[0])
		if has_port:
			p.data.sport = int(mapping[1])

		p.dst = dnet.ip_aton(mapping[2])
		if has_port:
			p.data.dport = int(mapping[3])
		
		tun.write(dnet.ip_checksum(p.pack()))
		#print ("Packet mapped: " + `mapping`)
	else:
		print ("Dropping packet, sorry about that :(")	
