from pathlib import Path
from tkinter import *
from tkinter import ttk

try:
    # Package-style import: python -m frontend.main
    from ..backend.RunScripts import RunScripts
except ImportError:
    # Script-style import: python frontend/main.py
    import sys

    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from backend.RunScripts import RunScripts

checkRunning = False

def runSystemCheck():
    global checkRunning
    if not checkRunning:
        checkRunning = True
        print("System check started...")
        # Simulate a system check with a delay
        root.after(2000, finishSystemCheck)  # Simulate a 2-second system check
    else:
        print("System check is already running.")


def finishSystemCheck():
    global checkRunning
    checkRunning = False
    print("System check finished.")

def itemPassed(label):
    label.config(foreground="green")
    ttk.Label(frm, text="Passed").grid(column=1, row=label.grid_info()['row'])

def itemFailed(label):
    label.config(foreground="red")
    ttk.Label(frm, text="Failed").grid(column=1, row=label.grid_info()['row'])


root = Tk()
frm = ttk.Frame(root, padding=10)
frm.grid()
ttk.Button(frm, text="Run System Check", command=lambda: runSystemCheck()).grid(column=0, row=0)
firewallProfileLabel = ttk.Label(frm, text="Firewall Status").grid(column=0, row=1)
tpmLabel = ttk.Label(frm, text="TPM Status").grid(column=0, row=2)
userPrivilegesLabel = ttk.Label(frm, text="User Privileges").grid(column=0, row=3)
missingUpdatesLabel = ttk.Label(frm, text="Missing Updates").grid(column=0, row=4)
systemLogConfigLabel = ttk.Label(frm, text="System Log Configuration").grid(column=0, row=5)
systemEncryptionLabel = ttk.Label(frm, text="System Encryption").grid(column=0, row=6)
localUserSettingsLabel = ttk.Label(frm, text="Local User Settings").grid(column=0, row=7)

root.mainloop()