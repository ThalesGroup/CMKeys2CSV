# ------------------------------------------------------------------#
# Module to read key material from CSV file
# and delete keys from CM
# ------------------------------------------------------------------#
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
parser.add_argument("-in",  nargs=1, action="store", dest="inFile", required=True, help="Input file with key identifiers for deletion")

# Args are returned as a LIST.  Separate them into individual strings
args = parser.parse_args()

# Display results from inputs
print("\n ---- CIPHERTRUST PARAMETERS ----")

Host = str(" ".join(args.Host))
Port = str(" ".join(args.Port))
User = str(" ".join(args.User))
Pass = str(" ".join(args.Pass))
inFile = str(" ".join(args.inFile))

# If password was not entered as a parameter, prompt the user for it.
if len(Pass) < 1:
    Pass = getpass.getpass('Enter user\'s password: ')

tmpStr = " Host: %s\n Port: %s\n User: %s\n Output: %s" %(Host, Port, User, inFile)
print(tmpStr)

# ################################################################################
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# ################################################################################

# Get Source and Destination Authorization Token/Strings
print("\n Accessing Source and collecting Authorization Strings...")

authStr, authStrBornOn = createCMAuthStr(Host, Port, User, Pass)

print("  * Host Access Confirmed *")
tmpStr = "    Username: %s\n" %(User)
print(tmpStr)

listOfKeys = readkeysFromFile(inFile)
t_ListLen = len(listOfKeys)

deletedKeyCount = 0
for key in listOfKeys:
    t_keyID = key["id"]
    t_keyName = key['name']


    print(f"\nKey Name: {t_keyName}  Key ID: {t_keyID}")
    success = deleteCMKey(Host, Port, t_keyID, authStr)

    if success:
        deletedKeyCount = deletedKeyCount + 1

    # Check to see if auth string needs to be refreshed
    if isAuthStrRefreshNeeded(authStrBornOn):
        authStr, authStrBornOn = createCMAuthStr(Host, Port, User, Pass) # refresh
        print(f"  --> Host Authorization Token Refreshed.  {deletedKeyCount} of {t_ListLen} Key Data Objects deleted so far...")
    
print(f"\n{deletedKeyCount} out of {len(listOfKeys)} keys were successfully deleted")

# printJList("The Key List", listOfKeys)
