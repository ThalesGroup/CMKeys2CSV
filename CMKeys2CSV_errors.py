#####################################################################################
#
# 	Name: CMKeys2CSV_errors.py
# 	Author: Rick R
# 	Purpose:  Error routines to support k-rest.py
#                      
#####################################################################################
import json

def kPrintError(t_str, t_r):
# -----------------------------------------------------------------------------
# The objective is to print the error information back in the even that a HTTPS
# response is not STATUS_OK
# -----------------------------------------------------------------------------
    t_str_sc    = str(t_r.status_code)
    t_str_r     = str(t_r.reason)
    # if 'error' in str(t_r.json()):
        # t_str_e     = str(t_r.json()['error'])
    # else:
        # t_str_e     = str(t_r.json())
    t_str_e = t_str

    tmpstr      = "  --> %s Status Code: %s\n   Reason: %s\n   Error: %s" %(t_str, t_str_sc, t_str_r, t_str_e)
    
    print(tmpstr)

    return
