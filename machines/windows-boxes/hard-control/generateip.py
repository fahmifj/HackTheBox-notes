from netaddr import IPNetwork
for ip in IPNetwork('192.168.4.0/24'):
	print(ip)

