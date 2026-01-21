#####################################################################################
#
# 	Name: CMKeys2CSV.py
# 	Author: Rick R
# 	Purpose:  Python-based Key List Data Extractor (but no key material)
#                   
#####################################################################################

import  argparse
from    CMKeys2CSV_REST import createCMAuthStr, getHostObjList, getHostObjData, getHostExternalCAList, getHostLocalCAList, getHostCertificateData
import  CMKeys2CSV_REST
from    CMKeys2CSV_errors import *
import  getpass
import  copy
import  pandas as pd # https://pandas.pydata.org/docs/reference/api/pandas.read_excel.html

# ---------------- Constants ----------------------------------------------------
DEFAULT_SRC_PORT   = ["443"]

# ################################################################################

# ----- INPUT PARSING BEGIN ------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message 
# will be printed automatically
parser = argparse.ArgumentParser(prog="CMKeys2CSV.py", description="REST-based Key List Extractor for CipherTrust Manager")

# Src Information
parser.add_argument("-host", nargs=1, action="store", dest="Host", required=True, help="IP address or FQDN of CipherTrust")
parser.add_argument("-port", nargs=1, action="store", dest="Port", default=DEFAULT_SRC_PORT, help="Listen port on CipherTrust.  Default is 443")
parser.add_argument("-user", nargs=1, action="store", dest="User", required=True, help="CipherTrust Username")
parser.add_argument("-pass", nargs=1, action="store", dest="Pass", required=False, help="CipherTrust Password")
parser.add_argument("-out",  nargs=1, action="store", dest="keyFile", required=True, help="Filename for CSV output file for keys")
parser.add_argument("-KMIPONLY", action=argparse.BooleanOptionalAction, required=False, type=bool, help="Optional flag to retriving only KMIP Key Info")
parser.add_argument("-certout",  nargs=1, action="store", dest="certFile", required=False, help="Filename for CSV output file for certificates and CAs")

# Args are returned as a LIST.  Separate them into individual strings
args = parser.parse_args()

t_cmHost = str(" ".join(args.Host))
t_cmPort = str(" ".join(args.Port))
t_cmUser = str(" ".join(args.User))
t_cmPass = str(" ".join(args.Pass))
keyFile = str(" ".join(args.keyFile))

if args.certFile:
    certFile = str(" ".join(args.certFile))
else:
    certFile = ""

# If password was not entered as a parameter, prompt the user for it.
if len(t_cmPass) < 1:
    t_cmPass = getpass.getpass('Enter user\'s password: ')

# check for to see if user wants to see only KMIP keys
KMIPOnly = False
if args.KMIPONLY:
    KMIPOnly = True

# Set Global Variables for REST module
CMKeys2CSV_REST.g_cmHost = t_cmHost
CMKeys2CSV_REST.g_cmPort = t_cmPort
CMKeys2CSV_REST.g_cmUser = t_cmUser
CMKeys2CSV_REST.g_cmPass = t_cmPass


# Display results from inputs
print("\n ---- CIPHERTRUST PARAMETERS ----")
tmpStr = " Host: %s\n Port: %s\n User: %s\n Output: %s\n KMIPOnly?: %s" %(t_cmHost, t_cmPort, t_cmUser, keyFile, KMIPOnly)
if len(certFile) > 0:
    tmpStr += f"\n Certificate output: {certFile}"
print(tmpStr)

# ################################################################################
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# ################################################################################

# Get Source and Destination Authorization Token/Strings
print("\n Accessing Source and collecting Authorization Strings...")

CMKeys2CSV_REST.g_authStr, CMKeys2CSV_REST.g_authStrBornOn = createCMAuthStr()
print("  * Host Access Confirmed *")

if KMIPOnly:
    print("\n  -> Only retrieving KMIP Keys...")

print("\n  -> Retrieving List Key Objects from CipherTrust...")
listofKeyObjects      = getHostObjList()

print(f"  -> Retrieving {len(listofKeyObjects)} Key Data Objects from CipherTrust...")
listofKeyDataObjects  = getHostObjData(listofKeyObjects)
listofKMIPKeys  = []
listofAllKeys   = []
isKMIPKey       = False

# Manipulate the list detailed keys so that the KMIP:custom information is shared at the highest level
# This makes for easier importation into a CSV file
print(f"\n  -> Key Data Objects Retrieval Complete.  Parsing {len(listofKeyDataObjects)} Key Data Objects...")

for t_key in listofKeyDataObjects:
    isKMIPKey = False
    t_newKey = copy.deepcopy(t_key)

    if 'meta' in str(t_key):
        del t_newKey['meta']
        if 'kmip' in  str(t_key['meta']):
            isKMIPKey = True

            # If this is a KMIP Key, the following information is going to be helpful to retain
            if 'custom' in str(t_key['meta']['kmip']):
                t_customDetails = t_key['meta']['kmip']['custom']
                for t_detail in t_customDetails:
                    for t_kvk in t_detail.keys():
                        if t_kvk == 'type' or t_kvk == 'index':
                            continue
                        # print ("KMIP Attribute found:", t_kvk, t_detail[t_kvk])
                        t_newKey[t_kvk] = t_detail[t_kvk]

            # printJList("t_newKey:", t_newKey)
            listofKMIPKeys.append(t_newKey)
    listofAllKeys.append(t_newKey)


# The new list of keys will contain ONLY KMIP keys and will include all information at the same dictionary/JSON level.
keyCount = 0
if KMIPOnly:
    output_df = pd.DataFrame(listofKMIPKeys)
    output_df.to_csv(keyFile, index=False)
    keyCount = len(listofKMIPKeys)
else:
    output_df = pd.DataFrame(listofAllKeys)
    output_df.to_csv(keyFile, index=False)
    keyCount = len(listofAllKeys)

print(f"\nMeta data for {keyCount} keys has been exported to: {keyFile}")

# ################################################################################
# ---- CERTIFICATE AND CA RETRIEVAL ------------------------------------------------
if len(certFile) > 0:
    listofAllCAs = []
    listofAllCertificates = []

    caListofCAObjects      = getHostExternalCAList()
    print(f"  -> Retrieved {len(caListofCAObjects)} External CA Data Objects from CipherTrust...")
    # print (json.dumps(caListofCAObjects, indent=4))
    for ca in caListofCAObjects:
        ca['CAType'] = 'External'
        listofAllCAs.append(ca)

    caListofCAObjects      = getHostLocalCAList()
    print(f"  -> Retrieved {len(caListofCAObjects)} Local CA Data Objects from CipherTrust...")
    # print (json.dumps(caListofCAObjects, indent=4))
    for ca in caListofCAObjects:
        ca['CAType'] = 'Local'
        listofAllCAs.append(ca)

    caCount = len(listofAllCAs)

    caListofCertificateDataObjects  = getHostCertificateData(caListofCAObjects)
    certCount = len(caListofCertificateDataObjects)
    print(f"  -> Retrieved {certCount} Certificate Data Objects from CipherTrust...")

    for cert in caListofCertificateDataObjects:
        cert['CAType'] = 'Local'
        listofAllCertificates.append(cert)

    # print (json.dumps(listofAllCertificates, indent=4))

    combinedList = listofAllCAs + listofAllCertificates
    output_df = pd.DataFrame(combinedList)
    output_df.to_csv(certFile, mode = 'w', index=False, header=True)

    print(f"\nCertificate and Meta data for {caCount} CAs and {certCount} Certificates has been exported to: {certFile}\n")











