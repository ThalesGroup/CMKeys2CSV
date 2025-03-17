# CMKey2CSV_REAST
#
# definition file of assorted REST Commands for communicating
# with CipherTrust APIs
#
######################################################################
import  requests
from    urllib3.exceptions import InsecureRequestWarning
import  json
import  inspect
from    CMKeys2CSV_errors import *
from    CMKeys2CSV_enums import *


# ---------------- CONSTANTS -----------------------------------------------------
STATUS_CODE_OK      = 200
STATUS_CODE_CREATED = 201
APP_JSON            = "application/json"

CM_REST_PREAMBLE    = "/api/v1/"


def makeHexStr(t_val):
# -------------------------------------------------------------------------------
# makeHexString
# -------------------------------------------------------------------------------
    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr

def printJList(t_str, t_jList):
# -------------------------------------------------------------------------------
# A quick subscript that makes it easy to print out a list of JSON information in
# a more readable format.
# -------------------------------------------------------------------------------    
    print("\n ", t_str, json.dumps(t_jList, skipkeys = True, allow_nan = True, indent = 3))

def createCMAuthStr(t_cmHost, t_cmPort, t_cmUser, t_cmPass):
# -----------------------------------------------------------------------------
# REST Assembly for HOST LOGIN 
# 
# The objective of this section is to provide the username and password parameters
# to the REST interface of the CM host in return for a BEARER TOKEN that is 
# used for authentication of other commands.
# -----------------------------------------------------------------------------

    t_cmRESTAPI            = CM_REST_PREAMBLE + "auth/tokens/"
    t_cmHostRESTCmd        = "https://%s:%s%s" %(t_cmHost, t_cmPort, t_cmRESTAPI)  

    t_cmHeaders            = {"Content-Type":APP_JSON}
    t_cmBody               = {"name":t_cmUser, "password":t_cmPass}


    # Suppress SSL Verification Warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    # Note that CM does not required Basic Auth to retrieve information.  
    # Instead, the body of the call contains the username and password.
    r = requests.post(t_cmHostRESTCmd, data=json.dumps(t_cmBody), headers=t_cmHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        t_module = inspect.currentframe().f_code.co_name
        kPrintError(t_module + ":", r)
        exit()

    # Extract the Bearer Token from the value of the key-value pair of the JSON reponse which is identified by the 'jwt' key.
    t_cmUserBearerToken            = r.json()['jwt']
    t_cmAuthStr                    = "Bearer "+t_cmUserBearerToken

    return t_cmAuthStr

def getHostObjList(t_host, t_port, t_authStr):
# -----------------------------------------------------------------------------
# REST Assembly for Cllecting More detailed Host Key Info
# 
# The objective of this section is to use the host Authorization / Bearer Token
# to query the host's REST interface about keys.
#
# Note that the list returns only 500 keys per query.  As such, we are going to
# define a batch limit and make multiple queries to the CipherTrust Server
# -----------------------------------------------------------------------------

    t_batchLimit            = 500   # 500 keys per retreival
    t_batchSkip             = 0     # skip or offset into object count
    t_batchObjSkip          = t_batchLimit * t_batchSkip
    t_hostObjCnt            = 0

    # Define a common header for all REST API Requests
    t_hostHeaders            = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization": t_authStr}

    # Process all keys per the size of the t_batchLimit until you have retrieved all of them.
    # Although this is the initial batch, use the same command structure as if multiple batch calls
    # may be required - for consistency.
    t_hostRESTKeyList    = "%svault/keys2/?skip=%s&limit=%s" %(CM_REST_PREAMBLE, t_batchObjSkip, t_batchLimit)
    t_hostRESTCmd        = "https://%s:%s%s" %(t_host, t_port, t_hostRESTKeyList)   

    # Note that this REST Command does not require a body object in this GET REST Command
    r = requests.get(t_hostRESTCmd, headers=t_hostHeaders, verify=False)

    if(r.status_code != STATUS_CODE_OK):
        t_module = inspect.currentframe().f_code.co_name

        tmpStr = "%s: t_batchLimit:%s t_batchSkip:%s t_batchObSkip:%s" %(t_module, t_batchLimit, t_batchSkip, t_batchObjSkip)
        print(tmpStr)
        kPrintError(t_module + ":", r)
        exit()

    t_hostFinalObjList       = r.json()[CMAttributeType.RESOURCES.value]
    t_hostObjCnt             = len(t_hostFinalObjList)
    t_hostObjTotalCnt        = r.json()[CMAttributeType.TOTAL.value]

    # After the initial retreival, we have access to the total number of objects.
    # From there, determine, now many more iterations are requied.
    while t_hostObjTotalCnt > t_hostObjCnt:
        t_batchSkip             = t_batchSkip + 1               # iterate to next batch
        t_batchObjSkip          = t_batchLimit * t_batchSkip    # calculate number of objects to skip

        t_hostRESTKeyList       = "%svault/keys2/?skip=%s&limit=%s" %(CM_REST_PREAMBLE, t_batchObjSkip, t_batchLimit)
        t_hostRESTCmd           = "https://%s:%s%s" %(t_host, t_port, t_hostRESTKeyList)   

        # Note that this REST Command does not require a body object in this GET REST Command
        r = requests.get(t_hostRESTCmd, headers=t_hostHeaders, verify=False)

        if(r.status_code != STATUS_CODE_OK):
            t_module = inspect.currentframe().f_code.co_name
            tmpStr = "%s: t_hostObjTotalCnt:%s t_batchLimit:%s t_batchSkip:%s t_batchObjSkip:%s t_hostObjCnt:%s" %(t_module, t_hostObjTotalCnt, t_batchLimit, t_batchSkip, t_batchObjSkip, t_hostObjCnt)
            print(tmpStr)
            kPrintError(t_module + ":", r)
            exit()

        # Retreive the batch of objects
        t_ObjList       = r.json()[CMAttributeType.RESOURCES.value]

        # Add/extend the current batch to the total list (Final Obj List)
        t_hostFinalObjList.extend(t_ObjList)
        t_hostObjCnt = len(t_hostFinalObjList)

    # print("\n         host Objects: ",  t_hostFinalObjList[0].keys())
    return t_hostFinalObjList

def getHostObjData(t_host, t_port, t_ObjList, t_authStr):
# -----------------------------------------------------------------------------
# REST Assembly for obtaining specific Object Data from CipherTrust
#
# Using the VAULT/KEYS2 API above, the host delivers all but the actual
# key block of object.  This section collectios more detailed ata.
# -----------------------------------------------------------------------------

    t_hostRESTAPI            = CM_REST_PREAMBLE + "vault/keys2"
    
    t_hostObjDataList       = [] # created list to be returned later
    t_ObjCnt                = 0  # Initialize counter
    t_ListLen               = len(t_ObjList)
    
    for obj in range(t_ListLen):
        hostObjID    = t_ObjList[obj][CMAttributeType.ID.value]
        hostObjName  = t_ObjList[obj][CMAttributeType.NAME.value]

        # If the object is not exportable, then an error code will be returned.  So, check for exportability prior to
        # attempting to export the key material from the host.

        t_hostRESTCmd = "https://%s:%s%s/%s" %(t_host, t_port, t_hostRESTAPI, hostObjID)
        t_hostHeaders = {"Content-Type":APP_JSON, "Accept":APP_JSON, "Authorization":t_authStr}

        # Note that REST Command does not require a body object in this GET REST Command
        r = requests.get(t_hostRESTCmd, headers=t_hostHeaders, verify=False)
        if(r.status_code != STATUS_CODE_OK):
            t_module = inspect.currentframe().f_code.co_name
            kPrintError(t_module + ":", r)

            hostObjName  = t_ObjList[obj][CMAttributeType.NAME.value]
            print("  Obj ID:%s, Name: %s" %(hostObjID, hostObjName) )

            continue

        t_data      = r.json()        
        t_hostObjDataList.append(t_data)  #Add data to te list
        
       
        t_ObjCnt += 1

    return t_hostObjDataList

# -------------------------------------------------------------------
def csvWriteFile(t_outFile, t_list):
# -------------------------------------------------------------------    
    # import os.path
    # from os import path
    import csv

    with open(t_outFile, 'w', newline='') as outFile:
        csvWriter = csv.writer(outFile, dialect='excel')

        keycnt = 0
        for kobj in t_list:
            if 'aliases' in kobj.keys():
                del kobj['aliases']
            if 'meta' in kobj.keys():
                del kobj['meta']

            if keycnt == 0: # if first entry, add header
                header = kobj.keys()
                csvWriter.writerow(header)
            
            values = kobj.values() # write values to file
            csvWriter.writerow(values)
            keycnt =+ 1

        
    outFile.close()
    success = True
    return success
