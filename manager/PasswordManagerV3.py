import hashlib
import json
import os
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, simpledialog

infoFile = Path(__file__).parent / "info.enc"
keyFile = Path(__file__).parent / "key.bin"

defData = {
    "Settings": {"password": "admin"},
    "Instances": [],
}

data = {}
listbox = None
root = None


def encrypt(data):
    raw = json.dumps(data, indent=2).encode("utf-8")
    key = os.urandom(len(raw))
    encrypted = bytes(b ^ k for b, k in zip(raw, key))
    try:
        infoFile.write_bytes(encrypted)
        keyFile.write_bytes(key)
    except OSError as e:
        messagebox.showerror("Error", f"Error saving encrypted data: {e}")


def decrypt():
    try:
        encrypted = infoFile.read_bytes()
        key = keyFile.read_bytes()
    except FileNotFoundError:
        return defData
    except OSError as e:
        messagebox.showerror("Error", f"Error reading data: {e}")
        return defData

    if len(encrypted) != len(key):
        messagebox.showerror("Error", "Data/key length mismatch — file may be corrupt.")
        return defData

    raw = bytes(b ^ k for b, k in zip(encrypted, key))
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        messagebox.showerror("Error", f"Failed to decode data: {e}")
        return defData


def hashPw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def checkMaster(entered) -> bool:
    return hashPw(entered) == data["Settings"]["password"]


def refreshList():
    listbox.delete(0, tk.END)
    for i, inst in enumerate(data.get("Instances", [])):
        listbox.insert(
            tk.END, f"{i + 1}. {inst['context']} — {inst['name']} — {inst['password']}"
        )


def askInstanceFields(title, defaults=("", "", "")):
    context = simpledialog.askstring(title, "Context:", initialvalue=defaults[0])
    if context is None:
        return None
    name = simpledialog.askstring(title, "Name:", initialvalue=defaults[1])
    if name is None:
        return None
    password = simpledialog.askstring(title, "Password:", initialvalue=defaults[2])
    if password is None:
        return None
    return context, name, password


def addInstance():
    fields = askInstanceFields("Add Instance")
    if fields is None:
        return
    context, name, password = fields
    data["Instances"].append({"context": context, "name": name, "password": password})
    encrypt(data)
    refreshList()


def removeInstance():
    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("Warning", "Please select an instance to remove.")
        return
    data["Instances"].pop(selection[0])
    encrypt(data)
    refreshList()


def editInstance():
    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("Warning", "Please select an instance to edit.")
        return
    index = selection[0]
    instance = data["Instances"][index]
    defaults = (instance["context"], instance["name"], instance["password"])
    fields = askInstanceFields("Edit Instance", defaults)
    if fields is None:
        return
    context, name, password = fields
    data["Instances"][index] = {"context": context, "name": name, "password": password}
    encrypt(data)
    refreshList()


def changeMasterPassword():
    current = simpledialog.askstring("Settings", "Current master password:", show="*")
    if current is None or not checkMaster(current):
        messagebox.showerror("Error", "Incorrect current password.")
        return
    new_pw = simpledialog.askstring("Settings", "New master password:", show="*")
    if not new_pw:
        return
    confirm = simpledialog.askstring("Settings", "Confirm new password:", show="*")
    if new_pw != confirm:
        messagebox.showerror("Error", "Passwords do not match.")
        return
    data["Settings"]["password"] = hashPw(new_pw)
    encrypt(data)
    messagebox.showinfo("Settings", "Master password updated.")


def loginLoop() -> bool:
    while True:
        entered = simpledialog.askstring(
            "Login", "Enter application password:", parent=root, show="*"
        )
        if entered is None:
            return False
        if checkMaster(entered):
            return True
        messagebox.showerror("Login", "Incorrect password. Try again.")


def on_quit():
    encrypt(data)
    root.destroy()


def main():
    global data, listbox, root

    data = decrypt()

    stored = data["Settings"]["password"]
    if len(stored) != 64:
        data["Settings"]["password"] = hashPw(stored)
        encrypt(data)

    BG = "#2b2b2b"
    FG = "#e0e0e0"
    ENTRY = "#3c3c3c"
    BTN = "#404040"
    BTN_HOV = "#505050"
    FONT = ("Arial", 12)
    HEADER = ("Segoe UI", 20, "bold")
    BTN_CFG = dict(
        bg=BTN,
        fg=FG,
        activebackground=BTN_HOV,
        activeforeground=FG,
        width=10,
        height=5,
        pady=10,
    )

    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("500x450")
    root.resizable(False, False)
    root.configure(bg=BG)
    root.withdraw()

    if not loginLoop():
        root.destroy()
        return

    root.deiconify()

    header_frame = tk.Frame(root, bg=BG)
    header_frame.pack(side="top", fill="x")

    button_frame = tk.Frame(root, bg=BTN, width=16)
    button_frame.pack(side="left", fill="y")

    list_frame = tk.Frame(root, bg=BG)
    list_frame.pack(side="right", fill="both", expand=True)

    tk.Label(header_frame, text="Password Manager", font=HEADER, bg=BG, fg=FG).pack(
        pady=10
    )

    listbox = tk.Listbox(
        list_frame, activestyle="none", bg=ENTRY, fg=FG, font=FONT, selectmode=tk.SINGLE
    )
    listbox.pack(side="left", fill="both", expand=True, padx=(0, 2))

    scrollbar = tk.Scrollbar(list_frame, command=listbox.yview, bg=BTN)
    scrollbar.pack(side="right", fill="y", pady=4)
    listbox.config(yscrollcommand=scrollbar.set)

    for text, cmd in [
        ("➕", addInstance),
        ("➖", removeInstance),
        ("✏️", editInstance),
        ("⚙️", changeMasterPassword),
    ]:
        tk.Button(button_frame, text=text, command=cmd, **BTN_CFG).pack(side="top")

    root.protocol("WM_DELETE_WINDOW", on_quit)
    refreshList()
    root.mainloop()


if __name__ == "__main__":
    main()
