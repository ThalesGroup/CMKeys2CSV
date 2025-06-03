# ------------------------------------------------------------------#
# Module to read key material from CSV file
# and delete keys from CM
# ------------------------------------------------------------------#
import  argparse
from    CMKeys2CSV_errors import *
from    CMKeys2CSV_REST import *

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
parser.add_argument("-pass", nargs=1, action="store", dest="Pass", required=True, help="CipherTrust Password")
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

tmpStr = " Host: %s\n Port: %s\n User: %s\n Output: %s" %(Host, Port, User, inFile)
print(tmpStr)

# ################################################################################
# ---- MAIN MAIN MAIN ------------------------------------------------------------
# ################################################################################

# Get Source and Destination Authorization Token/Strings
print("\n Accessing Source and collecting Authorization Strings...")

authStr      = createCMAuthStr(Host, Port, User, Pass)
print("  * Host Access Confirmed *")
tmpStr = "    Username: %s\n" %(User)
print(tmpStr)

listOfKeys = readkeysFromFile(inFile)
deletedKeyCount = 0

for key in listOfKeys:
    t_keyID = key["id"]
    t_keyName = key['name']

    print(f"\nKey Name: {t_keyName}  Key ID: {t_keyID}")
    success = deleteCMKey(Host, Port, t_keyID, authStr)

    if success:
        deletedKeyCount =+ 1
    
print(f"\n{deletedKeyCount} out of {len(listOfKeys)} keys were deleted")

# printJList("The Key List", listOfKeys)
