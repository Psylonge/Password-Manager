import json
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, simpledialog

infoFile = Path(__file__).parent / "info.json"

defaultJson = {
    "Settings": {"password": "admin"},
    "Instances": [],
}

data = {}
listbox = None
root = None


def loadData():
    try:
        with open(infoFile, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return defaultJson


def saveData(data):
    try:
        with open(infoFile, "w") as file:
            json.dump(data, file, indent=2)
    except Exception as e:
        messagebox.showerror("Error", f"Error saving data: {e}")


def refreshList(data):
    global listbox
    listbox.delete(0, tk.END)
    instances = data.get("Instances", [])

    for i, inst in enumerate(instances):
        listbox.insert(
            tk.END,
            f"{i + 1}. {inst['context']} - {inst['name']} - {inst['password']}",
        )


def addInstance(data):
    global listbox

    context = simpledialog.askstring("Add Instance", "Context:")
    if context is None:
        return

    name = simpledialog.askstring("Add Instance", "Name:")
    if name is None:
        return

    password = simpledialog.askstring("Add Instance", "Password:")
    if password is None:
        return

    new_instance = {"context": context, "name": name, "password": password}
    data["Instances"].append(new_instance)

    saveData(data)
    refreshList(data)


def removeInstance(data):
    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("Warning", "Please select an instance to remove")
        return

    index = selection[0]
    removed = data["Instances"].pop(index)
    saveData(data)
    refreshList(data)


def editInstance(data, listbox):
    selection = listbox.curselection()
    if not selection:
        messagebox.showwarning("Warning", "Please select an instance to edit")
        return

    index = selection[0]
    instance = data["Instances"][index]

    context = simpledialog.askstring(
        "Edit Instance", "Context:", initialvalue=instance["context"]
    )
    if context is None:
        return

    name = simpledialog.askstring(
        "Edit Instance", "Name:", initialvalue=instance["name"]
    )
    if name is None:
        return

    password = simpledialog.askstring(
        "Edit Instance", "Password:", initialvalue=instance["password"]
    )
    if password is None:
        return

    data["Instances"][index] = {"context": context, "name": name, "password": password}
    saveData(data)
    refreshList(data)


def quit():
    global data
    saveData(data)
    root.destroy()


def main():
    global data, listbox, root

    data = loadData()

    bg_color = "#2b2b2b"
    fg_color = "#e0e0e0"
    entry_bg = "#3c3c3c"
    button_bg = "#404040"
    button_hover = "#505050"

    defaultFont = ("Arial", 12)
    headerFont = ("Segoe UI", 20, "bold")

    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("500x450")
    root.resizable(False, False)
    root.configure(bg=bg_color)

    root.withdraw()

    while True:
        pe = simpledialog.askstring(
            "Login", "Enter application password:", parent=root, show="*"
        )
        if pe == data["Settings"]["password"]:
            break
        elif messagebox.CANCEL:
            root.destroy()
            return
        elif pe is None:
            messagebox.showerror("Error", "Incorrect password")

    root.deiconify()

    header_frame = tk.Frame(root, bg=bg_color)
    header_frame.pack(side="top", fill="x")

    list_frame = tk.Frame(root, bg=bg_color)
    list_frame.pack(side="right", fill="both", expand=True)

    button_frame = tk.Frame(root, bg=button_bg, width=16)
    button_frame.pack(side="left", fill="y", expand=False)

    header = tk.Label(
        header_frame,
        text="Password Manager",
        font=headerFont,
        bg=bg_color,
        fg=fg_color,
    )
    header.pack(pady=10)

    listbox = tk.Listbox(
        list_frame,
        activestyle="none",
        bg=entry_bg,
        fg=fg_color,
        font=defaultFont,
        selectmode=tk.SINGLE,
    )
    listbox.pack(side="left", fill="both", expand=True, padx=(0, 2))

    scrollbar = tk.Scrollbar(list_frame, command=listbox.yview, bg=button_bg)
    scrollbar.pack(side="right", fill="y", pady=4)

    listbox.config(yscrollcommand=scrollbar.set)

    tk.Button(
        button_frame,
        text="➕",
        command=lambda: addInstance(data),
        bg=button_bg,
        fg=fg_color,
        activebackground=button_hover,
        activeforeground=fg_color,
        width=10,
        height=5,
        pady=10,
    ).pack(side="top")

    tk.Button(
        button_frame,
        text="➖",
        command=lambda: removeInstance(data),
        bg=button_bg,
        fg=fg_color,
        activebackground=button_hover,
        activeforeground=fg_color,
        width=10,
        height=5,
        pady=10,
    ).pack(side="top")

    tk.Button(
        button_frame,
        text="✏️",
        command=lambda: editInstance(data, listbox),
        bg=button_bg,
        fg=fg_color,
        activebackground=button_hover,
        activeforeground=fg_color,
        width=10,
        height=5,
        pady=10,
    ).pack(side="top")

    tk.Button(
        button_frame,
        text="⚙️",
        bg=button_bg,
        fg=fg_color,
        activebackground=button_hover,
        activeforeground=fg_color,
        width=10,
        height=5,
        pady=10,
    ).pack(side="top")

    root.protocol("WM_DELETE_WINDOW", quit)

    refreshList(data)

    root.mainloop()


if __name__ == "__main__":
    main()
