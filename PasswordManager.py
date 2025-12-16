import json
import os
import base64
import logging

import tkinter as tk
from tkinter import messagebox, simpledialog

from pathlib import Path

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

json_file = Path(__file__).parent / "info.json"
salt_file = Path(__file__).parent / ".salt"
master_hash_file = Path(__file__).parent / ".master"

SESSION_TIMEOUT_MINUTES = 15
CLIPBOARD_CLEAR_SECONDS = 30

password = "admin"
salt = None
data = []

argon2_params = {
    "time_cost": 2,
    "memory_cost": 102400,
    "parallelism": 8,
    "hash_len": 32,
    "salt_len": 16,
}

def load_plaintext_settings():
    global password, argon2_params
    try:
        if not json_file.exists():
            return
        raw = json_file.read_text(encoding="utf-8").strip()
        if not raw:
            return
        obj = json.loads(raw)
        settings = obj.get("settings", {})

        try:
            argon2_params["time_cost"] = int(settings.get("time_cost", argon2_params["time_cost"]))
            argon2_params["memory_cost"] = int(settings.get("memory_cost", argon2_params["memory_cost"]))
            argon2_params["parallelism"] = int(settings.get("parallelism", argon2_params["parallelism"]))
            argon2_params["hash_len"] = int(settings.get("hash_len", argon2_params["hash_len"]))
            argon2_params["salt_len"] = int(settings.get("salt_len", argon2_params["salt_len"]))
        except Exception:
            logger.debug("Could not parse some Argon2 params from plaintext settings; using defaults.")

        password = settings.get("password", password)
    except Exception:

        logger.debug("Plaintext settings not loaded; info.json may be encrypted.")

def load_or_create_salt():
    global salt
    try:
        if salt_file.exists():
            raw = salt_file.read_text(encoding="utf-8").strip()
            if not raw:
                raise ValueError("Empty salt file")
            try:
                decoded = base64.b64decode(raw)
            except Exception:
                raise ValueError("Salt file is not valid base64")

            expected_len = argon2_params.get("salt_len", 16)
            if len(decoded) != expected_len:
                if len(decoded) < max(8, expected_len // 2):
                    raise ValueError(f"Salt length {len(decoded)} is too short")

            salt = decoded
            return

        salt = os.urandom(argon2_params["salt_len"])
        salt_file.write_text(base64.b64encode(salt).decode("utf-8"), encoding="utf-8")
    except Exception:
        try:
            if salt_file.exists():
                backup = salt_file.with_name(salt_file.name + ".bak")
                salt_file.replace(backup)
                logger.warning("Backed up invalid salt", backup)
        except Exception:
            logger.exception("Failed to back up invalid salt file")

        salt = os.urandom(argon2_params["salt_len"])
        try:
            salt_file.write_text(base64.b64encode(salt).decode("utf-8"), encoding="utf-8")
            logger.info("Generated new salt and wrote to %s", salt_file)
        except Exception:
            logger.exception("Failed to write new salt file")

def derive_key(master_password: str, salt: bytes) -> bytes:
    key = hash_secret_raw(
        master_password.encode("utf-8"),
        salt,
        time_cost=argon2_params["time_cost"],
        memory_cost=argon2_params["memory_cost"],
        parallelism=argon2_params["parallelism"],
        hash_len=argon2_params["hash_len"],
        type=Type.ID,
    )
    return key

def encrypt_data(plaintext: str, master_password: str, salt: bytes) -> str:
    key = derive_key(master_password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    plaintext_bytes = plaintext.encode("utf-8")
    padding_len = 16 - (len(plaintext_bytes) % 16)
    plaintext_bytes += bytes([padding_len] * padding_len)
    
    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode("utf-8")

def decrypt_data(encrypted_data: str, master_password: str, salt: bytes) -> str:
    try:
        key = derive_key(master_password, salt)
        encrypted_bytes = base64.b64decode(encrypted_data.encode("utf-8"))
        
        if len(encrypted_bytes) < 16:
            raise ValueError("Encrypted data is too short (missing IV)")
        
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        if len(plaintext_bytes) == 0:
            raise ValueError("Decrypted data is empty")
        
        padding_len = plaintext_bytes[-1]
        
        if padding_len > 16 or padding_len == 0 or padding_len > len(plaintext_bytes):
            raise ValueError("Invalid padding - wrong password or corrupted data")
        
        plaintext_bytes = plaintext_bytes[:-padding_len]
        
        try:
            return plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Invalid password or corrupted data - cannot decode")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def load_from_json():
    global data, password, salt
    load_or_create_salt()

    if not json_file.exists():
        messagebox.showinfo("Info", f"{json_file} not found. A new file will be created.")
        data = []
        try:
            save_to_json()
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create {json_file}: {e}")
            return False

    raw = None
    try:
        raw = json_file.read_text(encoding="utf-8")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read {json_file}: {e}")
        return False

    obj = None

    try:
        obj = json.loads(raw)
    except Exception:
 
        try:
            decrypted_content = decrypt_data(raw, password, salt)
            obj = json.loads(decrypted_content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read or decrypt {json_file}: {e}")
            return False

    settings = obj.get("settings", {})

    try:
        argon2_params["time_cost"] = int(settings.get("time_cost", argon2_params["time_cost"]))
        argon2_params["memory_cost"] = int(settings.get("memory_cost", argon2_params["memory_cost"]))
        argon2_params["parallelism"] = int(settings.get("parallelism", argon2_params["parallelism"]))
        argon2_params["hash_len"] = int(settings.get("hash_len", argon2_params["hash_len"]))
        argon2_params["salt_len"] = int(settings.get("salt_len", argon2_params["salt_len"]))
    except Exception:
        logger.debug("Invalid Argon2 settings in file; using current values.")

    password = settings.get("password", password)
    data = []
    
    for inst in obj.get("instances", []):
        ctx = inst.get("context", "")
        user = inst.get("user", inst.get("email", inst.get("username", "")))
        pwd = inst.get("password", "")
        data.append({"context": ctx, "user": user, "password": pwd})

    return True

def save_to_json():
    global salt
    
    if salt is None:
        load_or_create_salt()
    
    obj = {
        "settings": {
            "password": password,
            "time_cost": argon2_params.get("time_cost"),
            "memory_cost": argon2_params.get("memory_cost"),
            "parallelism": argon2_params.get("parallelism"),
            "hash_len": argon2_params.get("hash_len"),
            "salt_len": argon2_params.get("salt_len"),
        },
        "instances": [
            {
                "context": item.get("context", ""),
                "user": item.get("user", ""),
                "password": item.get("password", "")
            }
            for item in data
        ]
    }
    try:
        plaintext = json.dumps(obj, indent=2, ensure_ascii=False)
        encrypted_content = encrypt_data(plaintext, password, salt)
        json_file.write_text(encrypted_content, encoding="utf-8")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save {json_file}: {e}")

def wipe_all_data():
    """Generate new data, new salt, and wipe current data."""
    global data, salt
    
    confirmed = messagebox.askyesno(
        "Confirm Wipe",
        "This will delete ALL stored passwords and regenerate the salt.\n\nThis action cannot be undone. Continue?"
    )
    
    if not confirmed:
        return
    
    try:
        data = []
        salt = os.urandom(argon2_params["salt_len"])
        salt_file.write_text(base64.b64encode(salt).decode("utf-8"), encoding="utf-8")
        save_to_json()
        messagebox.showinfo("Success", "All data wiped and salt regenerated.")
        logger.info("All data wiped and salt regenerated.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to wipe data: {e}")
        logger.exception("Failed to wipe data")

def main():
    root = tk.Tk()
    root.title("Password Manager")
    root.geometry("400x420")
    root.resizable(False, False)
    
    bg_color = "#2b2b2b"
    fg_color = "#e0e0e0"
    entry_bg = "#3c3c3c"
    button_bg = "#404040"
    button_hover = "#505050"
    
    root.configure(bg=bg_color)

    root.withdraw()

    load_plaintext_settings()

    while True:
        pw = simpledialog.askstring("Login", "Enter application password:", parent=root, show="*")
        if pw is None:
            root.destroy()
            return
        global password
        password = pw
        load_or_create_salt()
        ok = load_from_json()
        if ok:
            break
        retry = messagebox.askretrycancel("Access denied", "Incorrect password or decryption failed. Retry?", parent=root)
        if not retry:
            root.destroy()
            return

    root.deiconify()
    root.protocol("WM_DELETE_WINDOW", lambda: (save_to_json(), root.destroy()))

    header = tk.Label(root, text="Password Manager", font=("Segoe UI", 16), bg=bg_color, fg=fg_color)
    header.pack(pady=8)

    container = tk.Frame(root, bg=bg_color)
    container.pack(fill="both", expand=True, padx=10, pady=6)

    list_frame = tk.Frame(container, bg=bg_color)
    list_frame.pack(side="top", fill="both", expand=True)

    listbox = tk.Listbox(list_frame, activestyle="none", bg=entry_bg, fg=fg_color, selectmode=tk.SINGLE)
    listbox.pack(side="left", fill="both", expand=True, padx=(0, 4), pady=4)
    
    scrollbar = tk.Scrollbar(list_frame, command=listbox.yview, bg=button_bg)
    scrollbar.pack(side="right", fill="y", pady=4)
    listbox.config(yscrollcommand=scrollbar.set)

    form = tk.Frame(container, bg=bg_color)
    form.pack(side="top", fill="x", pady=(8, 0))
    form.grid_columnconfigure(0, weight=0)
    form.grid_columnconfigure(1, weight=1)
    form.grid_columnconfigure(2, weight=1)
    form.grid_columnconfigure(3, weight=1)

    tk.Label(form, text="Context:", bg=bg_color, fg=fg_color).grid(row=0, column=0, sticky="e", padx=4, pady=4)
    context_var = tk.StringVar()
    context_entry = tk.Entry(form, textvariable=context_var, width=50, bg=entry_bg, fg=fg_color, insertbackground=fg_color)
    context_entry.grid(row=0, column=1, padx=4, pady=4, columnspan=2, sticky="w")

    tk.Label(form, text="Username:", bg=bg_color, fg=fg_color).grid(row=1, column=0, sticky="e", padx=4, pady=4)
    user_var = tk.StringVar()
    user_entry = tk.Entry(form, textvariable=user_var, width=50, bg=entry_bg, fg=fg_color, insertbackground=fg_color)
    user_entry.grid(row=1, column=1, padx=4, pady=4, columnspan=2, sticky="w")

    tk.Label(form, text="Password:", bg=bg_color, fg=fg_color).grid(row=2, column=0, sticky="e", padx=4, pady=4)
    pass_var = tk.StringVar()
    pass_entry = tk.Entry(form, textvariable=pass_var, show="*", width=50, bg=entry_bg, fg=fg_color, insertbackground=fg_color)
    pass_entry.grid(row=2, column=1, padx=4, pady=4, sticky="w")

    def refresh_listbox():
        listbox.delete(0, tk.END)
        for idx, item in enumerate(data):
            listbox.insert(tk.END, f"{idx+1}. {item.get('context','')} — {item.get('user','')} — {item.get('password','')}")

    editing_state = {"is_editing": False, "edit_index": None}

    def on_add():
        context = context_var.get().strip()
        username = user_var.get().strip()
        password_val = pass_var.get().strip()

        if not (context and username and password_val):
            messagebox.showwarning("Incomplete", "Fill all fields.")
            return

        if editing_state["is_editing"] and editing_state["edit_index"] is not None:
            data[editing_state["edit_index"]] = {"context": context, "user": username, "password": password_val}
            status.config(text="Edited.")
        else:
            data.append({"context": context, "user": username, "password": password_val})
            status.config(text="Saved.")

        refresh_listbox()
        context_var.set("")
        user_var.set("")
        pass_var.set("")
        editing_state["is_editing"] = False
        editing_state["edit_index"] = None

    def on_remove():
        selected = listbox.curselection()

        if not selected:
            messagebox.showwarning("Select", "Select an entry to remove.")
            return
        
        idx = selected[0]
        del data[idx]
        
        if editing_state["is_editing"] and editing_state["edit_index"] == idx:
            editing_state["is_editing"] = False
            editing_state["edit_index"] = None
        
        refresh_listbox()
        status.config(text="Removed.")

    def on_edit():
        selected = listbox.curselection()
        if not selected:
            messagebox.showwarning("Select", "Select an entry to edit.")
            return
        
        idx = selected[0]
        item = data[idx]
        context_var.set(item.get("context", ""))
        user_var.set(item.get("user", ""))
        pass_var.set(item.get("password", ""))
        editing_state["is_editing"] = True
        editing_state["edit_index"] = idx
        status.config(text="Editing...")

    button_frame = tk.Frame(form, bg=bg_color)
    button_frame.grid(row=3, column=1, columnspan=3, pady=10, sticky="w")

    def on_settings():
        settings_window = tk.Toplevel(root)
        settings_window.title("Encryption Settings")
        settings_window.geometry("400x300")
        settings_window.resizable(False, False)
        settings_window.configure(bg=bg_color)
        
        tk.Label(settings_window, text="Settings", font=("Segoe UI", 12, "bold"), bg=bg_color, fg=fg_color).pack(pady=10)
        
        params_frame = tk.Frame(settings_window, bg=bg_color)
        params_frame.pack(padx=15, pady=10, fill="both", expand=True)
        
        tk.Label(params_frame, text="Time Cost:", bg=bg_color, fg=fg_color).grid(row=0, column=0, sticky="e", padx=5, pady=5)
        time_cost_var = tk.StringVar(value=str(argon2_params["time_cost"]))
        tk.Entry(params_frame, textvariable=time_cost_var, width=20, bg=entry_bg, fg=fg_color, insertbackground=fg_color).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        tk.Label(params_frame, text="Memory Cost (KB):", bg=bg_color, fg=fg_color).grid(row=1, column=0, sticky="e", padx=5, pady=5)
        memory_cost_var = tk.StringVar(value=str(argon2_params["memory_cost"]))
        tk.Entry(params_frame, textvariable=memory_cost_var, width=20, bg=entry_bg, fg=fg_color, insertbackground=fg_color).grid(row=1, column=1, sticky="w", padx=5, pady=5)
        
        tk.Label(params_frame, text="Parallelism:", bg=bg_color, fg=fg_color).grid(row=2, column=0, sticky="e", padx=5, pady=5)
        parallelism_var = tk.StringVar(value=str(argon2_params["parallelism"]))
        tk.Entry(params_frame, textvariable=parallelism_var, width=20, bg=entry_bg, fg=fg_color, insertbackground=fg_color).grid(row=2, column=1, sticky="w", padx=5, pady=5)
        
        tk.Label(params_frame, text="Salt Length (bytes):", bg=bg_color, fg=fg_color).grid(row=3, column=0, sticky="e", padx=5, pady=5)
        salt_len_var = tk.StringVar(value=str(argon2_params["salt_len"]))
        tk.Entry(params_frame, textvariable=salt_len_var, width=20, bg=entry_bg, fg=fg_color, insertbackground=fg_color).grid(row=3, column=1, sticky="w", padx=5, pady=5)

        tk.Label(params_frame, text="New Password:", bg=bg_color, fg=fg_color).grid(row=4, column=0, sticky="e", padx=5, pady=5)
        app_pass_var = tk.StringVar(value="")
        tk.Entry(params_frame, textvariable=app_pass_var, show="*", width=20, bg=entry_bg, fg=fg_color, insertbackground=fg_color).grid(row=4, column=1, sticky="w", padx=5, pady=5)

        tk.Label(params_frame, text="Confirm New Password:", bg=bg_color, fg=fg_color).grid(row=5, column=0, sticky="e", padx=5, pady=5)
        app_confirm_var = tk.StringVar(value="")
        tk.Entry(params_frame, textvariable=app_confirm_var, show="*", width=20, bg=entry_bg, fg=fg_color, insertbackground=fg_color).grid(row=5, column=1, sticky="w", padx=5, pady=5)
        
        def regenerate_salt():
            global salt
            salt = os.urandom(argon2_params["salt_len"])
            salt_file.write_text(base64.b64encode(salt).decode("utf-8"), encoding="utf-8")
            try:
                save_to_json()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to re-save data after salt regeneration: {e}")
                return
            messagebox.showinfo("Success", "Salt regenerated and data re-encrypted.")
            settings_window.destroy()
        
        def save_settings():
            try:
                argon2_params["time_cost"] = int(time_cost_var.get())
                argon2_params["memory_cost"] = int(memory_cost_var.get())
                argon2_params["parallelism"] = int(parallelism_var.get())
                argon2_params["salt_len"] = int(salt_len_var.get())

                new_pw = app_pass_var.get().strip()
                confirm_pw = app_confirm_var.get().strip()
                global password
                if new_pw or confirm_pw:
                    if new_pw != confirm_pw:
                        messagebox.showerror("Error", "Passwords do not match.")
                        return
                    if new_pw:
                        password = new_pw
                try:
                    save_to_json()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save settings: {e}")
                    return

                messagebox.showinfo("Success", "Settings updated.")
                settings_window.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid input. Please enter integers only.")
        
        button_frame_settings = tk.Frame(settings_window, bg=bg_color)
        button_frame_settings.pack(pady=15)
        
        tk.Button(button_frame_settings, text="Save", width=12, command=save_settings, bg=button_bg, fg=fg_color, activebackground=button_hover, activeforeground=fg_color).pack(side="left", padx=5)
        tk.Button(button_frame_settings, text="Regenerate Salt", width=15, command=regenerate_salt, bg=button_bg, fg=fg_color, activebackground=button_hover, activeforeground=fg_color).pack(side="left", padx=5)
        tk.Button(button_frame_settings, text="Wipe All Data", width=15, command=wipe_all_data, bg="#5c2e2e", fg=fg_color, activebackground="#7a3a3a", activeforeground=fg_color).pack(side="left", padx=5)

    tk.Button(button_frame, text="Add", width=10, command=on_add, bg=button_bg, fg=fg_color, activebackground=button_hover, activeforeground=fg_color).pack(side="left", padx=6)
    tk.Button(button_frame, text="Remove", width=10, command=on_remove, bg=button_bg, fg=fg_color, activebackground=button_hover, activeforeground=fg_color).pack(side="left", padx=6)
    tk.Button(button_frame, text="Edit", width=10, command=on_edit, bg=button_bg, fg=fg_color, activebackground=button_hover, activeforeground=fg_color).pack(side="left", padx=6)
    tk.Button(button_frame, text="⚙️", width=8, command=on_settings, bg=button_bg, fg=fg_color, activebackground=button_hover, activeforeground=fg_color).pack(side="left", padx=6)
    
    status = tk.Label(root, text="Ready", bd=1, relief="sunken", anchor="w", bg=button_bg, fg=fg_color)
    status.pack(side="bottom", fill="x")

    refresh_listbox()
    root.mainloop()

if __name__ == "__main__":
    main()