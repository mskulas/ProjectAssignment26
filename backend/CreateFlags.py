import json
from pathlib import Path


# Parses raw RunScripts output and derives the security flags shown by the UI.
class RunScriptsOutputParser:
    # Message text that indicates potentially concerning system-log activity.
    SYSTEM_LOG_KEYWORDS = (
        "failed",
        "denied",
        "unauthorized",
        "tamper",
        "malware",
        "audit failure",
    )

    def __init__(self, json_path=None):
        # Default to the output file beside this script unless a path is supplied.
        self.json_path = (
            Path(json_path)
            if json_path is not None
            else Path(__file__).with_name("RunScripts_output.json")
        )
        with self.json_path.open("r", encoding="utf-8") as file:
            self.data = json.load(file)

        if not isinstance(self.data, dict):
            raise ValueError("RunScripts output must be a JSON object.")

        # Normalize collection values so later checks only receive records or an empty list.
        self.firewall_profiles = self._as_records(
            self.data.get("Firewall profiles")
        )
        self.tpm = self.data.get("TPM")
        self.user_privileges = self.data.get("User privileges")
        self.missing_updates = self._as_records(self.data.get("Missing updates"))
        self.system_log = self.data.get("System log")

        # Track report sections that were omitted or returned an explicit scan error.
        self.scan_errors = {}
        for section in (
            "Firewall profiles",
            "TPM",
            "User privileges",
            "Missing updates",
            "System log",
        ):
            if section not in self.data:
                self.scan_errors[section] = "Section is missing from the report."
            elif isinstance(self.data[section], dict) and "error" in self.data[section]:
                self.scan_errors[section] = str(self.data[section]["error"])

        # Evaluate the parsed sections once and expose a simple flag dictionary.
        self.flags = self.create_flags()

    @staticmethod
    def _as_records(value):
        # A dict is usually one scan record; list values may contain mixed item types.
        if isinstance(value, dict):
            return [] if "error" in value else [value]
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        return []

    @staticmethod
    def _is_false(value):
        # Accept PowerShell's booleans and zeroes as well as common text representations.
        if value is False:
            return True
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value == 0
        if isinstance(value, str):
            return value.strip().lower() in ("false", "disabled", "no")
        return False

    @staticmethod
    def _is_firewall_disabled(value):
        # Firewall "Enabled" values may arrive as JSON booleans or Windows enum values.
        if value is False:
            return True
        if isinstance(value, int) and not isinstance(value, bool):
            return value == 1
        if isinstance(value, str):
            return value.strip().lower() in ("false", "disabled", "no")
        return False

    @staticmethod
    def _is_true(value):
        # Normalize true-like values for fields such as admin privilege status.
        if value is True:
            return True
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return value == 1
        if isinstance(value, str):
            return value.strip().lower() in ("true", "enabled", "yes")
        return False

    @staticmethod
    def _is_allow(value):
        if isinstance(value, str):
            return value.strip().lower() == "allow"
        # NetSecurity action enum values serialize as 0=NotConfigured, 1=Block, 2=Allow.
        return isinstance(value, int) and not isinstance(value, bool) and value == 2

    def _tpm_needs_review(self):
        # TPM data is reviewed when a required status is missing or disabled.
        if not isinstance(self.tpm, dict) or "error" in self.tpm:
            return True
        fields = ("IsEnabled", "IsActivated", "IsOwned")
        return any(
            field not in self.tpm or self._is_false(self.tpm[field])
            for field in fields
        )

    def _system_log_needs_review(self):
        # Scan errors are separate from log findings and should not create a log flag.
        if not isinstance(self.system_log, dict) or "error" in self.system_log:
            return False

        message = str(self.system_log.get("Message", "")).lower()
        has_keyword = any(keyword in message for keyword in self.SYSTEM_LOG_KEYWORDS)
        entry_type = self.system_log.get("EntryType")
        # EntryType 1/2/16 identify Error, Warning, and FailureAudit events.
        is_concerning_type = (
            isinstance(entry_type, int)
            and not isinstance(entry_type, bool)
            and entry_type in (1, 2, 16)
        )
        return has_keyword or is_concerning_type

    def create_flags(self):
        # Extract the error text once so it can be checked without assuming its JSON shape.
        tpm_error = (
            str(self.tpm.get("error", "")).lower()
            if isinstance(self.tpm, dict)
            else str(self.tpm or "").lower()
        )
        admin = (
            self.user_privileges.get("IsAdmin")
            if isinstance(self.user_privileges, dict)
            else None
        )

        # Each key is a user-facing security condition and its value is a boolean result.
        return {
            "Firewall Disabled": any(
                self._is_firewall_disabled(profile.get("Enabled"))
                for profile in self.firewall_profiles
            ),
            "Default Inbound Allow": any(
                self._is_allow(profile.get("DefaultInboundAction"))
                for profile in self.firewall_profiles
            ),
            "Default Outbound Allow": any(
                self._is_allow(profile.get("DefaultOutboundAction"))
                for profile in self.firewall_profiles
            ),
            "Investigate TPM": self._tpm_needs_review(),
            "TPM Access Denied": "access denied" in tpm_error,
            "Admin Privileges": self._is_true(admin),
            "Missing updates": bool(self.missing_updates),
            "System log": self._system_log_needs_review(),
        }


# Converts numeric Windows and NetSecurity enums into labels suitable for display.
class RunScriptsOutputRenderer:
    # Field names are used to choose the correct enum mapping during recursive conversion.
    ENUM_VALUES = {
        "Enabled": {0: "NotConfigured", 1: "False", 2: "True"},
        "AllowInboundRules": {0: "NotConfigured", 1: "False", 2: "True"},
        "AllowLocalFirewallRules": {0: "NotConfigured", 1: "False", 2: "True"},
        "AllowLocalIPsecRules": {0: "NotConfigured", 1: "False", 2: "True"},
        "AllowUserApps": {0: "NotConfigured", 1: "False", 2: "True"},
        "AllowUserPorts": {0: "NotConfigured", 1: "False", 2: "True"},
        "DefaultInboundAction": {0: "NotConfigured", 1: "Block", 2: "Allow"},
        "DefaultOutboundAction": {0: "NotConfigured", 1: "Block", 2: "Allow"},
        "EntryType": {
            1: "Error",
            2: "Warning",
            4: "Information",
            8: "SuccessAudit",
            16: "FailureAudit",
        },
    }

    def __init__(self, data):
        # Renderers can accept either the source dictionary or a parser instance.
        if isinstance(data, RunScriptsOutputParser):
            data = data.data
        if not isinstance(data, dict):
            raise ValueError("RunScripts output must be a JSON object.")
        self.data = data

    def to_display_data(self):
        # Start recursion at the report root.
        return self._convert(self.data)

    def _convert(self, value, field_name=None):
        # Preserve nested dictionaries and lists while passing each key to its child values.
        if isinstance(value, dict):
            return {
                key: self._convert(item, key)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._convert(item) for item in value]

        # Translate only integer enum values; leave strings and other JSON types unchanged.
        mapping = self.ENUM_VALUES.get(field_name)
        if mapping is not None and type(value) is int:
            return mapping.get(value, f"Unknown ({value})")
        return value
