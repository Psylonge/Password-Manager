import hashlib
import json
import os
import secrets
import shutil
import string
import tkinter as tk
from difflib import SequenceMatcher
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

infoFile = Path(__file__).parent / "info.enc"
keyFile = Path(__file__).parent / "key.bin"
iconFile = Path(__file__).parent / "icon.ico"

authPassword = "password"
authKey = "key"

BG = "#2b2b2b"
BG2 = "#232323"
FG = "#e0e0e0"
FG_DIM = "#888888"
ENTRY = "#3c3c3c"
BTN = "#404040"
BTN_HOV = "#505050"
ACCENT = "#5b9bd5"
RED = "#c0392b"

FONT = ("Arial", 10)
FONT_SM = ("Arial", 9)
FONT_BOLD = ("Arial", 11, "bold")
HEADER_FONT = ("Segoe UI", 20, "bold")

BTN_CFG = dict(
    bg=BTN,
    fg=FG,
    activebackground=BTN_HOV,
    activeforeground=FG,
    width=8,
    height=4,
    pady=5,
    font=("Arial", 12),
    relief="flat",
    bd=0,
)

data = {}
listbox, root = None, None


def default_data() -> dict:
    return {
        "Settings": {
            "password": hashlib.sha256(b"admin").hexdigest(),
            "auth_mode": authPassword,
        },
        "Instances": [],
    }


def fileCheck() -> bool:
    hasInfo = infoFile.exists()
    hasKey = keyFile.exists()
    if hasInfo != hasKey:
        orphan = infoFile if hasInfo else keyFile
        messagebox.showwarning(
            "Corrupted Data",
            f"'{orphan.name}' was found without its pair.\n"
            "The data cannot be recovered and will be reset.",
        )
        infoFile.unlink(missing_ok=True)
        keyFile.unlink(missing_ok=True)
        return False
    return hasInfo and hasKey


def resetData() -> dict:
    infoFile.unlink(missing_ok=True)
    keyFile.unlink(missing_ok=True)
    return default_data()


def encrypt(data: dict):
    raw = json.dumps(data, indent=2).encode("utf-8")
    key = os.urandom(len(raw))
    enc = bytes(b ^ k for b, k in zip(raw, key))
    try:
        infoFile.write_bytes(enc)
        keyFile.write_bytes(key)
    except OSError as e:
        messagebox.showerror("Error", f"Failed to save encrypted data: {e}")


def decrypt() -> dict:
    if not fileCheck():
        return default_data()
    if not infoFile.exists():
        return default_data()
    try:
        enc = infoFile.read_bytes()
        key = keyFile.read_bytes()
    except OSError as e:
        messagebox.showerror("Error", f"Failed to read data: {e}")
        return resetData()
    if len(enc) != len(key):
        if messagebox.askyesno(
            "Corrupted Data",
            "Data/key length mismatch — files may be corrupt.\n"
            "Reset to defaults? (All stored passwords will be lost.)",
        ):
            return resetData()
        return default_data()
    raw = bytes(b ^ k for b, k in zip(enc, key))
    try:
        loaded = json.loads(raw.decode("utf-8"))

        loaded["Settings"].setdefault("auth_mode", authPassword)
        return loaded
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        messagebox.showerror(
            "Error", f"Failed to decode data: {e}\nResetting to defaults."
        )
        return resetData()


def hashPW(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def checkMasterPw(entered: str) -> bool:
    return hashPW(entered) == data["Settings"]["password"]


def getAuthMode() -> str:
    return data["Settings"].get("auth_mode", authPassword)


def verifyKey(path: str) -> bool:
    try:
        supplied = Path(path).read_bytes()
        stored = keyFile.read_bytes()
        return secrets.compare_digest(supplied, stored)
    except OSError:
        return False


def loginLoop() -> bool:
    mode = getAuthMode()

    if mode == authKey:
        while True:
            path = filedialog.askopenfilename(
                title="Select key file to unlock",
                filetypes=[("Key files", "*.bin"), ("All files", "*.*")],
                parent=root,
            )
            if not path:
                return False
            if verifyKey(path):
                return True
            retry = messagebox.askretrycancel(
                "Login", "Key file does not match. Try a different file?"
            )
            if not retry:
                return False
    else:
        while True:
            entered = simpledialog.askstring(
                "Login", "Enter master password:", parent=root, show="*"
            )
            if entered is None:
                return False
            if checkMasterPw(entered):
                return True
            messagebox.showerror("Login", "Incorrect password. Try again.")


def generatePw(length: int) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(chars) for _ in range(length))


def refreshList():
    listbox.delete(0, tk.END)
    for i, inst in enumerate(data.get("Instances", [])):
        listbox.insert(
            tk.END,
            f"{i + 1}. {inst['context']} — {inst['name']} — {inst['password']}",
        )


def copyPw():
    selection = listbox.curselection()
    if not selection:
        return
    inst = data["Instances"][selection[0]]
    root.clipboard_clear()
    root.clipboard_append(inst["password"])
    messagebox.showinfo("Copied", f"Password for '{inst['name']}' copied to clipboard.")


def searchInstance():
    search = simpledialog.askstring("Search", "Enter search term:")
    if not search:
        refreshList()
        return
    term = search.lower()
    listbox.delete(0, tk.END)
    for i, inst in enumerate(data["Instances"]):
        fuzzy_hit = SequenceMatcher(None, term, inst["name"].lower()).ratio() > 0.4
        exact_hit = term in inst["context"].lower() or term in inst["name"].lower()
        if fuzzy_hit or exact_hit:
            listbox.insert(
                tk.END,
                f"{i + 1}. {inst['context']} — {inst['name']} — {inst['password']}",
            )


def askInstFields(title: str, initial_values=None):
    context = simpledialog.askstring(
        title, "Context:", initialvalue=initial_values[0] if initial_values else ""
    )
    if context is None:
        return None
    name = simpledialog.askstring(
        title, "Name:", initialvalue=initial_values[1] if initial_values else ""
    )
    if name is None:
        return None
    password = simpledialog.askstring(
        title,
        "Password:",
        initialvalue=initial_values[2] if initial_values else generatePw(12),
    )
    if password is None:
        return None
    return context, name, password


def addInstance():
    root.withdraw()
    fields = askInstFields("Add Instance")
    root.deiconify()
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
    inst = data["Instances"][selection[0]]
    if messagebox.askyesno(
        "Confirm", f"Remove '{inst['name']}' from '{inst['context']}'?"
    ):
        data["Instances"].pop(selection[0])
        encrypt(data)
        refreshList()


def edtInstance():
    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("Warning", "Please select an instance to edit.")
        return
    root.withdraw()
    index = selection[0]
    instance = data["Instances"][index]
    fields = askInstFields(
        "Edit Instance",
        (instance["context"], instance["name"], instance["password"]),
    )
    root.deiconify()
    if fields is None:
        return
    context, name, password = fields
    data["Instances"][index] = {"context": context, "name": name, "password": password}
    encrypt(data)
    refreshList()


def changeMasterPw():
    current = simpledialog.askstring("Settings", "Current master password:", show="*")
    if current is None:
        return
    if not checkMasterPw(current):
        messagebox.showerror("Error", "Incorrect current password.")
        return
    newPW = simpledialog.askstring("Settings", "New master password:", show="*")
    if not newPW:
        return
    confirm = simpledialog.askstring("Settings", "Confirm new password:", show="*")
    if newPW != confirm:
        messagebox.showerror("Error", "Passwords do not match.")
        return
    data["Settings"]["password"] = hashPW(newPW)
    encrypt(data)
    messagebox.showinfo("Settings", "Master password updated.")


def changeAuthMode():
    current_mode = getAuthMode()

    if current_mode == authPassword:
        pw = simpledialog.askstring(
            "Switch Auth Mode",
            "Confirm master password to enable key-file login:",
            show="*",
        )
        if pw is None:
            return
        if not checkMasterPw(pw):
            messagebox.showerror("Error", "Incorrect password.")
            return
        data["Settings"]["auth_mode"] = authKey
        encrypt(data)
        messagebox.showinfo(
            "Auth Mode",
            "Login mode set to KEY FILE.\n\n"
            "On next launch you will be prompted to select key.bin to unlock the app.\n"
            "Keep key.bin safe — losing it locks you out permanently.",
        )
    else:
        path = filedialog.askopenfilename(
            title="Supply current key file to switch back to password login",
            filetypes=[("Key files", "*.bin"), ("All files", "*.*")],
        )
        if not path:
            return
        if not verifyKey(path):
            messagebox.showerror("Error", "Key file does not match.")
            return
        data["Settings"]["auth_mode"] = authPassword
        encrypt(data)
        messagebox.showinfo("Auth Mode", "Login mode set to PASSWORD.")


def changeKeyLocation():
    global keyFile
    new_dir = filedialog.askdirectory()
    if not new_dir:
        return
    dest = Path(new_dir) / keyFile.name
    try:
        shutil.move(str(keyFile), str(dest))
    except OSError as e:
        messagebox.showerror("Error", f"Failed to move key file: {e}")
        return
    keyFile = dest
    encrypt(data)
    messagebox.showinfo("Settings", f"Key file moved to:\n{dest}")


def importInfoFile():
    path = filedialog.askopenfilename(
        filetypes=[("JSON files", "*.json")], title="Import Info File"
    )
    if not path:
        return
    try:
        with open(path, "r") as f:
            imported = json.load(f)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file: {e}")
        return
    existing = {(i["context"], i["name"]) for i in data["Instances"]}
    added = 0
    for inst in imported.get("Instances", []):
        if inst.get("context") and (inst["context"], inst.get("name")) not in existing:
            data["Instances"].append(inst)
            added += 1
    encrypt(data)
    refreshList()
    messagebox.showinfo("Import", f"Imported {added} new instance(s).")


def exportInfoFile():
    current = simpledialog.askstring("Settings", "Current master password:", show="*")
    if current is None:
        return
    if not checkMasterPw(current):
        messagebox.showerror("Error", "Incorrect current password.")
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json")],
        title="Export Info File",
    )
    if not path:
        return
    export = {
        "Settings": {"password": "admin"},
        "Instances": data["Instances"],
    }
    try:
        with open(path, "w") as f:
            json.dump(export, f, indent=4)
        messagebox.showinfo(
            "Export", "Exported successfully.\n⚠ This file is unencrypted."
        )
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export: {e}")


def resetAllData():
    current = simpledialog.askstring(
        "Reset", "Confirm master password to reset ALL data:", show="*"
    )
    if current is None:
        return
    if not checkMasterPw(current):
        messagebox.showerror("Error", "Incorrect password.")
        return
    if not messagebox.askyesno(
        "Reset",
        "⚠ This will permanently delete ALL passwords and settings.\nAre you sure?",
    ):
        return
    global data
    data = resetData()
    encrypt(data)
    refreshList()
    messagebox.showinfo("Reset", "All data reset.\nMaster password is now 'admin'.")


def settings():
    win = tk.Toplevel(root)
    win.title("Settings")
    win.geometry("360x640")
    win.resizable(False, False)
    win.configure(bg=BG)
    win.grab_set()
    win.iconbitmap(iconFile)

    tk.Label(win, text="⚙  Settings", font=HEADER_FONT, bg=BG, fg=FG).pack(pady=(18, 4))
    tk.Frame(win, bg=ACCENT, height=2).pack(fill="x", padx=20, pady=(0, 8))

    def section(label: str):
        tk.Label(
            win,
            text=label.upper(),
            font=("Arial", 9, "bold"),
            bg=BG,
            fg=FG_DIM,
            anchor="w",
        ).pack(fill="x", padx=24, pady=(12, 2))

    def action_row(label: str, desc: str, cmd, danger: bool = False):
        card = tk.Frame(win, bg=BG2)
        card.pack(fill="x", padx=20, pady=2)
        inner = tk.Frame(card, bg=BG2)
        inner.pack(fill="x", padx=12, pady=(8, 2))
        fg_label = RED if danger else FG
        arrow_color = RED if danger else ACCENT
        tk.Label(
            inner, text=label, font=FONT_BOLD, bg=BG2, fg=fg_label, anchor="w"
        ).pack(side="left")
        tk.Button(
            inner,
            text="›",
            command=cmd,
            bg=BG2,
            fg=arrow_color,
            activebackground=BG2,
            activeforeground=arrow_color,
            font=("Arial", 18, "bold"),
            relief="flat",
            bd=0,
            cursor="hand2",
            width=2,
        ).pack(side="right")
        tk.Label(
            card, text=desc, font=("Arial", 10), bg=BG2, fg=FG_DIM, anchor="w"
        ).pack(fill="x", padx=12, pady=(0, 8))

    section("Security")
    action_row(
        "Change Master Password",
        "Update the password used to unlock the app.",
        changeMasterPw,
    )

    mode_label = (
        "Switch to Key-File Login"
        if getAuthMode() == authPassword
        else "Switch to Password Login"
    )
    mode_desc = (
        "Use key.bin instead of a password to unlock the app."
        if getAuthMode() == authPassword
        else "Use the master password instead of key.bin to unlock the app."
    )
    action_row(mode_label, mode_desc, changeAuthMode)

    action_row(
        "Change Key Location",
        "Move key.bin to a different directory.",
        changeKeyLocation,
    )

    section("Data")
    action_row(
        "Import Passwords",
        "Merge instances from a plain JSON backup file.",
        importInfoFile,
    )
    action_row(
        "Export Passwords", "Save an unencrypted JSON backup to disk.", exportInfoFile
    )

    section("Danger Zone")
    action_row(
        "Reset All Data",
        "Permanently delete all passwords and settings.",
        resetAllData,
        danger=True,
    )

    tk.Frame(win, bg=BTN, height=1).pack(fill="x", padx=20, pady=(14, 0))
    current_mode_str = "key file" if getAuthMode() == authKey else "password"
    tk.Label(
        win,
        text=f"info.enc + key.bin  •  OTP encrypted  •  auth: {current_mode_str}",
        font=("Arial", 9),
        bg=BG,
        fg=FG_DIM,
    ).pack(pady=6)


def onQuit():
    encrypt(data)
    root.destroy()


def main():
    global data, listbox, root

    data = decrypt()

    if len(data["Settings"]["password"]) != 64:
        data["Settings"]["password"] = hashPW(data["Settings"]["password"])
        encrypt(data)

    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("500x600")
    root.resizable(False, False)
    root.configure(bg=BG)
    root.iconbitmap(iconFile)
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

    tk.Label(
        header_frame, text="Password Manager", font=HEADER_FONT, bg=BG, fg=FG
    ).pack(pady=10)

    listbox = tk.Listbox(
        list_frame,
        activestyle="none",
        bg=ENTRY,
        fg=FG,
        font=FONT,
        selectmode=tk.SINGLE,
    )
    listbox.pack(side="left", fill="both", expand=True, padx=(0, 2))

    scrollbar = tk.Scrollbar(list_frame, command=listbox.yview, bg=BTN)
    scrollbar.pack(side="right", fill="y", pady=4)
    listbox.config(yscrollcommand=scrollbar.set)

    for text, cmd in [
        ("🔃", refreshList),
        ("🔎", searchInstance),
        ("➕", addInstance),
        ("➖", removeInstance),
        ("✏️", edtInstance),
        ("⚙️", settings),
    ]:
        tk.Button(button_frame, text=text, command=cmd, **BTN_CFG).pack(side="top")

    root.protocol("WM_DELETE_WINDOW", onQuit)
    listbox.bind("<Button-3>", lambda e: copyPw())
    refreshList()
    root.mainloop()


if __name__ == "__main__":
    main()
