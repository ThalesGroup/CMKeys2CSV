**CM2Keys2CSV**

This application reads the key information (not key material) from CipherTrust and exports it to a CSV file specified by the user.

Usage:

**python CM2Keys2CSV [-h] -host HOSTNAME [-port PORT] -user USERNAME -pass PASSWORD -out FILENAME [-KMIPONLY]** 

where:

HOSTNAME  - IP or FQDN of CipherTrust

[PORT]    - Listen port on CipherTrust, default:  443. Optional.

USERNAME  - Username on CipherTrust

PASSWORD  - Password corresponding to Username

FILENAME  - Output file name for CSV data 

[-KMIPONLY] - Boolean flagfor extracting ONLY KMIP key information.  Optional.  Without this flag, resulting file will NOT contain any vendor-specific KMIP extensions.

