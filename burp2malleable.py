import burpee
import sys
import os
from malleablec2 import Profile
from malleablec2.components import *
from termcolor import colored

toolbanner = """
█▄▄ █░█ █▀█ █▀█  ▀█  █▀▄▀█ ▄▀█ █░░ █░░ █▀▀ ▄▀█ █▄▄ █░░ █▀▀
█▄█ █▄█ █▀▄ █▀▀  █▄  █░▀░█ █▀█ █▄▄ █▄▄ ██▄ █▀█ █▄█ █▄▄ ██▄
https://github.com/CodeXTF2/Burp2Malleable
"""
print(colored(toolbanner,"cyan"))

#print functions
def printsuccess(msg):
  print(colored(colored("[+] ","green") + msg,attrs=["bold"]))

def printfail(msg):
  global errors
  print(colored("[!] ","red",attrs=['bold']) + colored(msg,"yellow",attrs=['bold']))

def printbold(msg):
  print(colored(msg,attrs=['bold']))

def printmsg(msg):
  print(colored("[*] ","cyan",attrs=["bold"]) + msg)

def blend(string):
    isok = False
    while not isok:
        print("The current value of the field is:\n" + colored(string,"green"))
        toreplace = input("\nWhat part would you like to replace with the data?\n> ")
        strarray = string.split(toreplace)
        while len(strarray) <2:
            strarray.append("")
        print(f"The resulting field will look something like this:\n" + colored(f"{strarray[0]}DDovyDgKGfg{strarray[1]}\n","green"))
        isok_str = input("Does this look ok? (Y/n)\n> ")
        if isok_str == '' or isok_str.lower() == 'y':
            isok=True

    return strarray[0],strarray[1]

def storelocation(item):
    global reqheaders
    global reqparams_dict
    prepend = ''
    append = ''
    location = input(f"Where do you want to store {item}?\n\t1. Header\n\t2. Body\n\t3. URI-Param\n>")
    if location == "1":
        print("These are your current headers")
        for x in reqheaders.keys():
            printmsg(x)
        headername = input("Header name: ")
        if headername in reqheaderlist:
            print("This header already exists.")
            prepend,append = blend(str(reqheaders.get(headername)))
            reqheaders.pop(headername)
        return ['header',headername,prepend,append]
    elif location == "3":
        print("These are your current params")
        for x in reqparams_dict.keys():
            printmsg(x)
        paramname = input("Param name: ")
        if paramname in reqparams_dict.keys():
            print(f"This parameter {paramname} already exists.")
            prepend,append = blend(reqparams_dict[paramname])
            reqparams_dict.pop(paramname)
        return ['uriparam',paramname,prepend,append]
    else:
        return ['body','']

#is the req body used already


# fix the files
reqfilename = sys.argv[1]
resfilename = sys.argv[2]

reqfile = open(reqfilename,"r",errors='ignore').read()
resfile = open(resfilename,"r",errors='ignore').read()

with open("tempreq","w+",errors='ignore') as f:
    f.write(reqfile.replace("\"","\'").replace("\\","\\\\"))

with open("tempres","w+",errors='ignore') as f:
    f.write(resfile.replace("\"","\'").replace("\\","\\\\"))

reqfile = open("tempreq").read()
resfile = open("tempres").read()
requri = reqfile.split("\n")[0].split(" ")[1].split("?")[0]
resbody = ''.join(resfile.split("\n\n")[1:])
reqbody = ''.join(reqfile.split("\n\n")[1:])
try:
    reqparams = reqfile.split("\n")[0].split(" ")[1].split("?")[1].split("&")
except:
    reqparams= ""

reqparams_dict = {}
for x in reqparams:
    x_split = x.split("=")
    key = x_split[0]
    value = x_split[1]
    reqparams_dict[key] = value
reqmethod = reqfile.split("\n")[0].split(" ")[0]

reqheaders, reqdata = burpee.parse_request("tempreq")
resheaders, resdata = burpee.parse_request("tempres")
os.remove("tempreq")
os.remove("tempres")
reqfile_commented = ""
for x in reqfile.split("\n"):
    reqfile_commented += "# " + x + "\n"

resfile_commented = ""
for x in resfile.split("\n"):
    resfile_commented += "# " + x + "\n"

reqheaderlist = []
for x in reqheaders.items():
    reqheaderlist.append(x[0])


original = "# Original HTTP request\n#\n" + reqfile_commented + "\n#"
original += "\n# Original HTTP response\n#\n" + resfile_commented + "\n#"
original += "#\n#\n"





uri_used = False
body_used = False
beaconmeta = storelocation("Beacon metadata")
while beaconmeta [0] == "body" and reqmethod != "POST":
    printfail(f"Request body may only be used in POST requests. This is a {reqmethod} request.")
    beaconmeta = storelocation("Beacon metadata")


beaconid = storelocation("Beacon ID")
while beaconid[0] == "body" and reqmethod != "POST":
    printfail(f"Request body may only be used in POST requests. This is a {reqmethod} request.")
    beaconid = storelocation("Beacon ID")
while beaconid[0] == "body" and body_used:
    printfail(f"Request body already in use")
    beaconid = storelocation("Beacon ID")
if beaconid[0] == "body":
    body_used = True



beaconresponse = storelocation("Beacon response")
while beaconresponse[0] == "body" and reqmethod != "POST":
    printfail(f"Request body may only be used in POST requests. This is a {reqmethod} request.")
    beaconresponse = storelocation("Beacon response")
while beaconresponse[0] == "body" and body_used:
    printfail(f"Request body already in use")
    beaconresponse = storelocation("Beacon ID")
if beaconid[0] == "body":
    body_used = True

taskingprepend = input("What would you like to prepend to the beacon taskings in the response body?\n> ")
taskingappend = input("What would you like to apppend to the beacon taskings in the response body?\n> ")

profilebanner = """
############################################################################
# Generated by Burp2Malleable - https://github.com/CodeXTF2/Burp2Malleable #     
# By: CodeX                                                                #
############################################################################
"""


#create our profile
profile = Profile.from_scratch()



#http.get block
http_get = HttpGetBlock()
http_get.set_option("verb", reqmethod)
http_get.set_option("uri", requri.lower())

client_get = ClientBlock()
metadata = MetadataBlock()
for x in reqheaders.items():
    client_get.add_statement("header", x[0], x[1])
for x in reqparams_dict.keys():
    client_get.add_statement("parameter", x, reqparams_dict.get(x))


metadata.add_statement("mask")
metadata.add_statement("base64url")

#metadata
if beaconmeta[0] == "body":
    metadata.add_statement("prepend",beaconmeta[2])
    metadata.add_statement("append",beaconmeta[3])
    metadata.add_statement("print")
    printmsg(f"Storing beacon metadata in request body")
elif beaconmeta[0] == "uriparam":
    metadata.add_statement("prepend",beaconmeta[2])
    metadata.add_statement("append",beaconmeta[3])
    metadata.add_statement("parameter",beaconmeta[1])
    printmsg(f"Storing beacon metadata in the URI parameter {beaconmeta[1]}")
else:
    metadata.add_statement("prepend",beaconmeta[2])
    metadata.add_statement("append",beaconmeta[3])
    metadata.add_statement("header",beaconmeta[1])
    printmsg(f"Storing beacon metadata in request header {beaconmeta[1]}")

client_get.add_code_block(metadata)
server_get = ServerBlock()
output_get = OutputBlock()

#add the response body
reshalf1 = resbody[:len(resbody)//2]
reshalf2 = resbody[len(resbody)//2:]

output_get.add_statement("mask")
output_get.add_statement("base64url")
output_get.add_statement("prepend",reshalf1)
output_get.add_statement("prepend",taskingprepend)
output_get.add_statement("append",taskingappend)
output_get.add_statement("append",reshalf2)
#beacon tasking
output_get.add_statement("print")



server_get.add_code_block(output_get)
for x in resheaders.items():
    server_get.add_statement("header", x[0], x[1])

http_get.add_code_block(client_get)
http_get.add_code_block(server_get)




#http.post block
http_post = HttpPostBlock()
http_post.set_option("verb", reqmethod)
if requri == "/":
    requri += "/"
http_post.set_option("uri", requri.upper())


#http.post.client
client_post = ClientBlock()
for x in reqparams_dict.keys():
    client_post.add_statement("parameter", x, reqparams_dict.get(x))
#add the output_post block for the client
output_post = OutputBlock()
output_post.add_statement("mask")
output_post.add_statement("base64url")

#beaconupload
if beaconresponse[0] == "body":
    #add the req body
    reqhalf1 = reqbody[:len(reqbody)//2]
    reqhalf2 = reqbody[len(reqbody)//2:]
    output_post.add_statement("prepend",reqhalf1)
    output_post.add_statement("append",reqhalf2)
    output_post.add_statement("print")
    printmsg(f"Storing beacon response in request body")
elif beaconresponse[0] == "uriparam":
    output_post.add_statement("parameter",beaconresponse[1])
    printmsg(f"Storing beacon response in the URI parameter {beaconresponse[1]}")
else:
    output_post.add_statement("header",beaconresponse[1])
    printmsg(f"Storing beacon response in request header {beaconresponse[1]}")


post_id = IdBlock()
post_id.add_statement("mask")
post_id.add_statement("base64url")
#beaconid
if beaconid[0] == "body":
    post_id.add_statement("print")
    printmsg(f"Storing beacon ID in request body")
elif beaconid[0] == "uriparam":
    post_id.add_statement("parameter",beaconid[1])
    printmsg(f"Storing beacon ID in the URI Parameter {beaconid[1]}")
else:
    post_id.add_statement("header",beaconid[1])
    printmsg(f"Storing beacon ID in request header {beaconid[1]}")


for x in reqheaders.items():
    client_post.add_statement("header", x[0], x[1])

client_post.add_code_block(post_id)
client_post.add_code_block(output_post)



#http.post.server
server_post = ServerBlock()

#add the output_post block for the server
output_post = OutputBlock()
output_post.add_statement("mask")
output_post.add_statement("base64url")
output_post.add_statement("print")
server_post.add_code_block(output_post)








for x in resheaders.items():
    server_post.add_statement("header", x[0], x[1])

http_post.add_code_block(client_post)
http_post.add_code_block(server_post)


#build the profile
profile.add_code_block(http_get)
profile.add_code_block(http_post)

with open("generated.profile","w+") as f:
    f.write(profilebanner + str(profile))
printsuccess("Profile saved in generated.profile. Remember to run ./c2lint!")