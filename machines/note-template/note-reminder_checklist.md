# Reconnaissance/Information Gathering

## Service Enumeration

- A Web apps? 
  - Explore it, page source, note the input vectors, checkout: response, cookie, url brute force.
- FTP Anonymous?
  - Do I have write access?
- SMB?
  - Have access? down them all.
- Find no attack surface (max. 30min)? Try another service 
- What about full scan or UDP?

## Finding Exploit

- Cannot find the exploit? How about different keyword?
- Still can not find it? Am I missing something? Double check it by reenumeration.

# Exploitation

- PoC not work? Is it not returning the output back? What about redirect the stderr to stdout?
- Reverse shell is not coming back? Have you tried using another port (e.g. 443, 53)?

# Post Exploit --> PrivEsc

- What OS? Kernel?
- Where Am I? Any credentials in current working dir/or my home dir? 
  - Do I have a password and in stable shell? check sudo privs.
- What permission do I have? What group? 
- Who else have a shell?
- Is there any readable sensive files or writeable files by me?
- SUID or custom binary?
- What services and process is currently running? Is there an internal web?
  - Web server config?