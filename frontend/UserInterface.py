from tkinter import *
from tkinter import ttk

root = Tk()
frm = ttk.Frame(root, padding=10)
frm.grid()
ttk.Button(frm, text="Run System Check", command=lambda: print("System Check Running...")).grid(column=0, row=0)
ttk.Button(frm, text="Exit", command=root.destroy).grid(column=1, row=0)

root.mainloop()