import base64
import json
import subprocess
import Scripts


def PrintData(value, indent=0):
    prefix = " " * indent

    if isinstance(value, dict):
        if not value:
            print(f"{prefix}(no fields)")
            return

        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print(f"{prefix}{key}:")
                PrintData(item, indent + 2)
            else:
                print(f"{prefix}{key}: {item}")
    elif isinstance(value, list):
        if not value:
            print(f"{prefix}(no items)")
            return

        for index, item in enumerate(value, start=1):
            print(f"{prefix}[{index}]")
            PrintData(item, indent + 2)
    else:
        print(f"{prefix}{value}")


def RunScripts():
    script_provider = Scripts.Scripts()
    scripts = {
        "Firewall profiles": script_provider.GetNetFirewallProfile(),
        "TPM": script_provider.GetTPM(),
        "User privileges": script_provider.CheckUserPrivileges(),
        "Missing updates": script_provider.CheckForMissingUpdates(),
        "System log": script_provider.GetLoggingConfig(),
    }

    for name, script in scripts.items():
        print(f"\n--- {name} ---")

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
            print(f"PowerShell error:\n{error}")
            continue

        output = result.stdout.strip()
        if not output:
            print("(no output)")
            continue

        try:
            data = json.loads(output)
        except json.JSONDecodeError as error:
            print(f"Output was not valid JSON ({error}); raw output:")
            print(output or "(no output)")
            continue

        PrintData(data)


def main():
    RunScripts()


if __name__ == "__main__":
    main()