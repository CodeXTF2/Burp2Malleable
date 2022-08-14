# Burp2Malleable
This is a quick python utility I wrote to turn HTTP requests from burp suite into Cobalt Strike Malleable C2 profiles.  
As of now, it currently does not perform custom mangling such as prepend, append and encodings, but rather generates the rough profile with a default encoding of mask+base64. You are expected to add your own prepends, appends and encoding if you want to make it more convincing. I am working on ways to automate this as well.

## Installation
```
pip install -r requirements.txt
```
## Usage
```
python burp2malleable.py request.txt response.txt
```
  
Work in progress, will be updated if I think of ideas. Feel free to submit issues/PRs/suggestions.

## TODO
- Detect base64 strings in original request and response and automatically use those to store beacon data