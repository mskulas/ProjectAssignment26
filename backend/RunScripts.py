import json
import subprocess
import Scripts

def RunScripts(self):
    scripts = {
        "Firewall profiles": Scripts.GetNetFirewallProfile(),
        "TPM": Scripts.GetTPM(),
        "User privileges": Scripts.CheckUserPrivileges(),
        "Missing updates": Scripts.CheckForMissingUpdates(),
        "System log": Scripts.GetLoggingConfig(),
    }

    for name, script in scripts.items():
        print(f"\n--- {name} ---")

        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"],
            input="$ErrorActionPreference = 'Stop'\ntry {\n"
                  + script
                  + "\n} catch { [Console]::Error.WriteLine($_); exit 1 }",
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(f"PowerShell error:\n{result.stderr.strip()}")
            continue

        output = result.stdout.strip()
        try:
            print(json.dumps(json.loads(output), indent=2))
        except json.JSONDecodeError:
            print(output or "(no output)")