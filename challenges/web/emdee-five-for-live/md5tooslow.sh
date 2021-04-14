#!/bin/bash

req=$(curl -s -c mycookies http://46.101.16.203:30035/ | grep -i '<h3' | cut -d '<' -f4 | cut -d '>' -f2  | md5sum | cut -d ' ' -f1) 
curl -s -v -b mycookies --data-urlencode "hash=$req" http://46.101.16.203:30035