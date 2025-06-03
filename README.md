**CMKeys2CSV**

This application reads the key information (not key material) from CipherTrust and exports it to a CSV file specified by the user.

Usage:

**python CMKeys2CSV.py [-h] -host HOSTNAME [-port PORT] -user USERNAME -pass PASSWORD -out FILENAME [-KMIPONLY]** 

where:

HOSTNAME  - IP or FQDN of CipherTrust

[PORT]    - Listen port on CipherTrust, default:  443. Optional.

USERNAME  - Username on CipherTrust

PASSWORD  - Password corresponding to Username

FILENAME  - Output file name for CSV data 

[-KMIPONLY] - Boolean flag for extracting ONLY KMIP key information.  Optional.  Without this flag, resulting file will NOT contain any vendor-specific KMIP extensions.


**CMKeysDelete**

An additional application that assists with bulk deletion of keys.  After running CMKeys2CSV, the output file generated can be modifed
to list only those keys the user wishes to delete.  The modified CSV file is then sent as intput to CMKeysDelete.  All keys listed
in that file are then deleted with CMKeysDelete is executed.

Usage:

**python CMKeysDelete.py [-h] -host HOSTNAME [-port PORT] -user USERNAME -pass PASSWORD -in FILENAME** 

where:

HOSTNAME  - IP or FQDN of CipherTrust

[PORT]    - Listen port on CipherTrust, default:  443. Optional.

USERNAME  - Username on CipherTrust

PASSWORD  - Password corresponding to Username

FILENAME  - Input file name with CSV data (keys to be deleted)