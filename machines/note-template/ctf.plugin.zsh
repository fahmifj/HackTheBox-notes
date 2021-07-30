#!/bin/bash

function get_ip(){
   # It can be thm or htb IP
   tunnel_ip=`ifconfig tun0 2>/dev/null | grep netmask | awk '{print $2}'`
   # Use eth0 as default IP,
   default_ip=`ifconfig eth0 2>/dev/null | grep netmask | awk '{print $2}'`
   if [[ $tunnel_ip == *"10."* ]]; then
      echo $tunnel_ip
   else
      echo $default_ip
   fi
}

function mknote(){
  mkdir nmap gobuster loot logs exploits ssh-keys dump post-exploits
  cat << EOF > ./$1-notes.md
# 00 - Loot

Credentials:

| Service | Username | Password | Found at |
| ------- | -------- | -------- | -------- |
|         |          |          |          |
|         |          |          |          |
|         |          |          |          |

Valid Usernames

```

```

Emails

```

```

...

# 10 - Reconnaissance

## Port scanning - Nmap

### TCP

Full scan.

```
nmap -p- --min-rate 1000 --reason -oA nmap/10-tcp-allport-$boxname$ 10.10.10.10
```

### UDP

Top 20 TCP

# 15 - Enumeration

## TCP 21 - FTP

## TCP 80 - Website



# 20 - Foothold



# 25 - Privilege Escalation



# 30 - Post-Exploit



# 90 - Summary

Foothold: 

- 
- 

Privilege Escalation:

- 
- 

# 99 - Trial-error/Try list

> What to put here:
>
> - Options you want to try (upper=highest priority, lower=try later)
> - Track things you have tried but failed.
> - Tips/Trick you learned during completing the box.
> - Take a rest if you keep putting/looking your note in here for more than 45 minutes.

EOF

}
# https://askubuntu.com/questions/750419/how-do-i-run-a-sudo-command-needing-password-input-in-the-background
#alias sudo='sudo -v; [ $? ] && sudo '
alias sudo='sudo '
alias htbon='openvpn ~/.ovpnconfig/htb-sg.ovpn 1>/dev/null &'
alias htbfort='openvpn ~/.ovpnconfig/htb-fortress.ovpn 1>/dev/null &'
alias htbrel='openvpn ~/.ovpnconfig/htb-release.ovpn 1>/dev/null &'
alias thmon='openvpn ~/.ovpnconfig/thm.ovpn 1>/dev/null &'
alias thmwreath='openvpn ~/.ovpnconfig/thm-wreath.ovpn 1>/dev/null &'
alias kvpn='pkill openvpn'
alias hostit='python3 -m http.server 8000 -d ~/tools'
alias start='xdg-open'