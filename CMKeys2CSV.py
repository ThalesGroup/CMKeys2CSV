#####################################################################################
#
# 	Name: CMKeys2CSV.py
# 	Author: Rick R
# 	Purpose:  Python-based Key List Data Extractor (but no key material)
#                   
#####################################################################################

import  argparse
from    CMKeys2CSV_errors import *
from    CMKeys2CSV_REST import *
import  getpass

# ---------------- Constants ----------------------------------------------------
DEFAULT_SRC_PORT    = ["443"]

# ################################################################################

# ----- INPUT PARSING BEGIN ------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message 
# will be printed automatically
parser = argparse.ArgumentParser(prog="CMKeys2CSV.py", description="REST-based Key List Extractor for CipherTrust Manager")

# Src Information
parser.add_argument("-host", nargs=1, action="store", dest="Host", required=True, help="IP address or FQDN of CipherTrust")
parser.add_argument("-port", nargs=1, action="store", dest="Port", default=DEFAULT_SRC_PORT, help="Listen port on CipherTrust.  Default is 443")
parser.add_argument("-user", nargs=1, action="store", dest="User", required=True, help="CipherTrust Username")
parser.add_argument("-pass", nargs=1, action="store", dest="Pass", required=False, default = "", help="CipherTrust Password")
parser.add_argument("-out",  nargs=1, action="store", dest="outFile", required=True, help="FIlename for CSV output file")
parser.add_argument("-KMIPONLY", action=argparse.BooleanOptionalAction, required=False, type=bool, help="Optional flag to retriving only KMIP Key Info")

# Args are returned as a LIST.  Separate them into individual strings
args = parser.parse_args()

Host = str(" ".join(args.Host))
Port = str(" ".join(args.Port))
User = str(" ".join(args.User))
Pass = str(" ".join(args.Pass))
outFile = str(" ".join(args.outFile))

# If password was not entered as a parameter, prompt the user for it.
if len(Pass) < 1:
    Pass = getpass.getpass('Enter user\'s password: ')

# check for to see if user wants to see only KMIP keys
KMIPOnly = False
if args.KMIPONLY:
    KMIPOnly = True

# Display results from inputs
print("\n ---- CIPHERTRUST PARAMETERS ----")
tmpStr = " Host: %s\n Port: %s\n User: %s\n Output: %s\n KMIPOnly?: %s" %(Host, Port, User, outFile, KMIPOnly)
print(tmpStr)

# ################################################################################
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# ################################################################################

# Get Source and Destination Authorization Token/Strings
print("\n Accessing Source and collecting Authorization Strings...")

authStr = createCMAuthStr(Host, Port, User, Pass)
print("  * Host Access Confirmed *")

listOfKeys      = getHostObjList(Host, Port, authStr)
listofAllKeys   = getHostObjData(Host, Port, listOfKeys, authStr)
listofKMIPKeys  = []
isKMIPKey       = False

# printJList("listofAllKeys:", listofAllKeys)

# Manipulate the list detailed keys so that the KMIP:custom information is shared at the highest level
# This makes for easier importation into a CSV file

for t_key in listofAllKeys:
    isKMIPKey = False
    t_newKey = t_key.copy()

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


# The new list of keys will contain ONLY KMIP keys and will include all information at the same dictionary/JSON level.
keyCount = 0
if KMIPOnly:
    csvWriteFile(outFile, listofKMIPKeys)
    keyCount = len(listOfKeys)
else:
    csvWriteFile(outFile, listofAllKeys)
    keyCount = len(listOfKeys)

print(f"\nMeta data for {keyCount} keys has successfully been exported to: {outFile}.")









