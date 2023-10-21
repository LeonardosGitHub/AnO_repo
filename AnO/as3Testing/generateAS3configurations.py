import json,random,ipaddress,shutil
from string import Template

fileToLoad = "as3_DeclarationExplicitProxy.json"
iteration = 1
stop = 100000  # Can't be greater than 4294967295, this determines the number of new "clients"

#makes sure file is at original state
shutil.copyfile("orig_as3_DeclarationExplicitProxy.json",fileToLoad)

def appendSrciptodatagroup(iteration,stop):
    with open(fileToLoad, 'r') as file:
        jsonObj = {}        
        # read
        jsonObj = json.load(file)
    while iteration < (stop+1):
        #iteration = str(iteration)
        name = "client"
        
        # creates IP address from iteration number, and creates datagroup name
        key = "%s/32" % (ipaddress.IPv4Address(iteration))
        value = "datagroup-%s%s" % (name,str(iteration))
        
        #creates new entry for srcipToDatagroup
        jsonSrcipBlob = {"key": "", "value": ""}
        jsonSrcipBlob["key"] = key
        jsonSrcipBlob["value"] = value
        
        #creates new datagroup for new client above
        jsonClientBlobName = jsonSrcipBlob["value"]
        jsonClientdgBlob = {"class": "Data_Group","keyDataType": "string","records": [{"key": "f5.com","value": "all_uris"},{"key": "server.proxy.com","value": "all_uris"}]}
        
        # inserts/appends new entry for srcipToDatagroup into json
        jsonObj["Common"]["Shared"]["srcipToDatagroup"]["records"].append(jsonSrcipBlob)
        
        # inserts new datagroup for new client above into json
        jsonObj["Common"]["Shared"][jsonClientBlobName] = jsonClientdgBlob
        
        iteration += 1

    #creates new json object with above changes
    newData = json.dumps(jsonObj, indent=4)
    
    # writes above back to original file
    with open(fileToLoad, 'w') as file:
        # write
        file.write(newData)


i = 1
appendSrciptodatagroup(i,stop)
shutil.copyfile(fileToLoad, "as3_DeclarationExplicitProxy_"+str(stop)+".json")
