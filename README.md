# Burp2Malleable
This is a quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles.  
#### Update: Prepend and append support added!

## Installation
```
pip install -r requirements.txt
```
## Usage
```
python burp2malleable.py request.txt response.txt
```
  
### Example request and response
```
GET / HTTP/1.1
Host: example.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close



HTTP/1.1 200 OK
Accept-Ranges: bytes
Age: 441594
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Sun, 14 Aug 2022 17:45:50 GMT
Etag: "3147526947"
Expires: Sun, 21 Aug 2022 17:45:50 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECS (oxr/832D)
Vary: Accept-Encoding
X-Cache: HIT
Content-Length: 1256
Connection: close

<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;
        
    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>    
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>

```
  
### Example generated profile
```

############################################################################
# Generated by Burp2Malleable - https://github.com/CodeXTF2/Burp2Malleable #     
# By: CodeX                                                                #
############################################################################
# Automatically generated with pyMalleableC2
# https://github.com/Porchetta-Industries/pyMalleableC2
#
# !!! Make sure to run this profile through c2lint before using !!!

http-get {
    set verb "GET";
    set uri "/";
    client {
        header "Host" "example.com";
        header "Upgrade-Insecure-Requests" "1";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36";
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
        header "Accept-Encoding" "gzip, deflate";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Connection" "close";
        metadata {
            mask;
            base64url;
            header "Cookie";
        }
    }
    server {
        output {
            mask;
            base64url;
            print;
        }
        header "Accept-Ranges" "bytes";
        header "Age" "441594";
        header "Cache-Control" "max-age=604800";
        header "Content-Type" "text/html; charset=UTF-8";
        header "Date" "Sun, 14 Aug 2022 17:45:50 GMT";
        header "Etag" "'3147526947'";
        header "Expires" "Sun, 21 Aug 2022 17:45:50 GMT";
        header "Last-Modified" "Thu, 17 Oct 2019 07:18:26 GMT";
        header "Server" "ECS (oxr/832D)";
        header "Vary" "Accept-Encoding";
        header "X-Cache" "HIT";
        header "Content-Length" "1256";
        header "Connection" "close";
    }
}
http-post {
    set verb "GET";
    set uri "//";
    client {
        header "Host" "example.com";
        header "Upgrade-Insecure-Requests" "1";
        header "User-Agent" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36";
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
        header "Accept-Encoding" "gzip, deflate";
        header "Accept-Language" "en-US,en;q=0.9";
        header "Connection" "close";
        id {
            mask;
            base64url;
            parameter "id";
        }
        output {
            mask;
            base64url;
            header "data";
        }
    }
    server {
        output {
            mask;
            base64url;
            print;
        }
        header "Accept-Ranges" "bytes";
        header "Age" "441594";
        header "Cache-Control" "max-age=604800";
        header "Content-Type" "text/html; charset=UTF-8";
        header "Date" "Sun, 14 Aug 2022 17:45:50 GMT";
        header "Etag" "'3147526947'";
        header "Expires" "Sun, 21 Aug 2022 17:45:50 GMT";
        header "Last-Modified" "Thu, 17 Oct 2019 07:18:26 GMT";
        header "Server" "ECS (oxr/832D)";
        header "Vary" "Accept-Encoding";
        header "X-Cache" "HIT";
        header "Content-Length" "1256";
        header "Connection" "close";
    }
}

```

### ./c2lint
```
===============
default
===============

http-get
--------
GET / HTTP/1.1
Host: example.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Cookie: YfIEOvrR57hbCoYlnsBx5TjB5IA

HTTP/1.1 200 OK
Content-Length: 1256
Accept-Ranges: bytes
Age: 441594
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Sun, 14 Aug 2022 17:45:50 GMT
Etag: '3147526947'
Expires: Sun, 21 Aug 2022 17:45:50 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECS (oxr/832D)
Vary: Accept-Encoding
X-Cache: HIT
Connection: close

bqR9F2BLvQLP2VBRQVzNVl4w4tclwhAdyf8206NJ8opj6t-JT1cYgjODWx6U0851dR4JgFXXKpUxpxHmmxUTy1sKZ-M

http-post
---------
GET //?id=DDovyDgKGfg HTTP/1.1
Host: example.com
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
data: 4IUomDfekj7kAc56vQLFOw5fTsM

HTTP/1.1 200 OK
Content-Length: 1256
Accept-Ranges: bytes
Age: 441594
Cache-Control: max-age=604800
Content-Type: text/html; charset=UTF-8
Date: Sun, 14 Aug 2022 17:45:50 GMT
Etag: '3147526947'
Expires: Sun, 21 Aug 2022 17:45:50 GMT
Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
Server: ECS (oxr/832D)
Vary: Accept-Encoding
X-Cache: HIT
Connection: close

NpJwUg


[+] POST 3x check passed
[+] .http-get.server.output size is good
[+] .http-get.client size is good
[+] .http-post.client size is good
[+] .http-get.client.metadata transform+mangle+recover passed (1 byte[s])
[+] .http-get.client.metadata transform+mangle+recover passed (100 byte[s])
[+] .http-get.client.metadata transform+mangle+recover passed (128 byte[s])
[+] .http-get.client.metadata transform+mangle+recover passed (256 byte[s])
[+] .http-get.server.output transform+mangle+recover passed (0 byte[s])
[+] .http-get.server.output transform+mangle+recover passed (1 byte[s])
[+] .http-get.server.output transform+mangle+recover passed (48248 byte[s])
[+] .http-get.server.output transform+mangle+recover passed (1048576 byte[s])
[+] .http-post.client.id transform+mangle+recover passed (4 byte[s])
[+] .http-post.client.output transform+mangle+recover passed (0 byte[s])
[+] .http-post.client.output transform+mangle+recover passed (1 byte[s])
[+] .http-post.client.output chunks results
[+] .http-post.client.output transform+mangle+recover passed (33 byte[s])
[+] .http-post.client.output transform+mangle+recover passed (128 byte[s])
[+] Beacon profile specifies an HTTP Cookie header. Will tell WinINet to allow this.
```

Work in progress, will be updated if I think of ideas. Feel free to submit issues/PRs/suggestions.

## TODO
- Detect base64 strings in original request and response and automatically use those to store beacon data
  
  
## Credits
- https://github.com/Porchetta-Industries/pyMalleableC2
- https://github.com/xscorp/Burpee