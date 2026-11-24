import base64
import json
import subprocess
from pathlib import Path

import Scripts


def RunScripts():
    script_provider = Scripts.Scripts()
    scripts = {
        "Firewall profiles": script_provider.GetNetFirewallProfile(),
        "TPM": script_provider.GetTPM(),
        "User privileges": script_provider.CheckUserPrivileges(),
        "Missing updates": script_provider.CheckForMissingUpdates(),
        "System log": script_provider.GetLoggingConfig(),
    }
    results = {}

    for name, script in scripts.items():
        command = (
            "$ErrorActionPreference = 'Stop'\n"
            "$ProgressPreference = 'SilentlyContinue'\n"
            "try {\n"
            + script
            + "\n} catch { [Console]::Error.WriteLine($_); exit 1 }"
        )
        encoded_command = base64.b64encode(
            command.encode("utf-16le")
        ).decode("ascii")
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded_command,
            ],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            error = result.stderr.strip() or f"PowerShell exited with code {result.returncode}."
            results[name] = {"error": error, "returncode": result.returncode}
            continue

        output = result.stdout.strip()
        if not output:
            results[name] = None
            continue

        try:
            results[name] = json.loads(output)
        except json.JSONDecodeError as error:
            results[name] = {
                "error": f"PowerShell returned invalid JSON: {error}",
                "raw_output": output,
            }

    output_file = Path(__file__).with_name("RunScripts_output.json")
    with output_file.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=2, ensure_ascii=False)


def main():
    RunScripts()


if __name__ == "__main__":
    main()