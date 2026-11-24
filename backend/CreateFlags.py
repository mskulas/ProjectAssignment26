import json
from pathlib import Path

def CreateFlags():
    # define the flags we are looking for
    flags = {
        "Firewall Disabled": False,
        "Default Inbound Allow": False,
        "Default Outbound Allow": False,
        "Investigate TPM": False,
        "TPM Access Denied": False,
        "Admin Privileges": False,
        "Missing updates": False,
        "System log": False,
    }
    return flags