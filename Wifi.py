import subprocess
import re
import tkinter as tk
from tkinter import ttk, messagebox

# Global flag to toggle sensitive info like password/signal
show_sensitive = False

# Global dictionary to store fetched WiFi data
wifi_info = {}

# Function to get SSID, signal strength, MAC address, and band
def get_ssid():
    """
    Uses `netsh wlan show interfaces` to get:
    - SSID (connected network)
    - Signal strength in %
    - Physical address (MAC)
    - Band (e.g., 2.4GHz or 5GHz based on radio type)
    """
    try:
        output = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], encoding="utf-8")

        ssid_match = re.search(r"^\s*SSID\s*:\s*(.+)$", output, re.MULTILINE)
        signal_match = re.search(r"^\s*Signal\s*:\s*(\d+)%", output, re.MULTILINE)
        mac_match = re.search(r"^\s*Physical address\s*:\s*(.+)$", output, re.MULTILINE)
        radio_match = re.search(r"^\s*Radio type\s*:\s*(.+)$", output, re.MULTILINE)

        ssid = ssid_match.group(1).strip() if ssid_match else None
        signal = signal_match.group(1).strip() + "%" if signal_match else "Unknown"
        mac = mac_match.group(1).strip() if mac_match else "N/A"
        band = "2.4GHz" if "802.11b" in radio_match.group(1) or "802.11g" in radio_match.group(1) else "5GHz" \
            if "802.11a" in radio_match.group(1) or "802.11ac" in radio_match.group(1) else "Unknown"

        return ssid, signal, mac, band

    except Exception:
        return None, "N/A", "N/A", "N/A"

# Function to get WiFi password and encryption info
def get_password(ssid):
    """
    Uses `netsh wlan show profile` to extract:
    - Authentication type
    - Cipher
    - Security key presence
    - Saved WiFi password (if stored)
    """
    try:
        cmd = f'netsh wlan show profile name="{ssid}" key=clear'
        output = subprocess.check_output(cmd, shell=True, encoding="utf-8")

        auth_match = re.search(r"Authentication\s*:\s*(.+)", output)
        cipher_match = re.search(r"Cipher\s*:\s*(.+)", output)
        key_match = re.search(r"Security key\s*:\s*(.+)", output)
        pass_match = re.search(r"Key Content\s*:\s*(.+)", output)

        return {
            "SSID": ssid,
            "Authentication": auth_match.group(1).strip() if auth_match else "N/A",
            "Cipher": cipher_match.group(1).strip() if cipher_match else "N/A",
            "Security Key": key_match.group(1).strip() if key_match else "N/A",
            "Password": pass_match.group(1).strip() if pass_match else "Not stored"
        }

    except subprocess.CalledProcessError:
        return None

# Updates the info displayed in GUI

def update_info():
    """
    Main function to fetch all WiFi data and store it.
    Calls display_info() to update the GUI labels.
    """
    global wifi_info
    ssid, signal, mac, band = get_ssid()

    if not ssid:
        messagebox.showerror("Error", "Not connected to any WiFi network.")
        return

    info = get_password(ssid)
    if not info:
        messagebox.showerror("Error", "Unable to fetch WiFi security info.")
        return

    # Add signal, mac, band to the dictionary
    info["Signal Strength"] = signal
    info["Physical Address"] = mac
    info["Band"] = band

    wifi_info = info  # Save data globally
    display_info()

# Controls what is shown on the GUI
def display_info():
    """
    Updates all GUI label widgets with either actual data or masked values
    depending on show_sensitive state.
    """
    for key in labels:
        value = wifi_info.get(key, "N/A")
        if key in ["Password", "Signal Strength"] and not show_sensitive:
            labels[key].config(text="******")
        else:
            labels[key].config(text=value)

# Toggle button handler
def toggle_sensitive():
    """
    Toggles the visibility of password and signal strength.
    """
    global show_sensitive
    show_sensitive = not show_sensitive
    toggle_btn.config(text="Hide Sensitive Info" if show_sensitive else "Show Sensitive Info")
    display_info()

# ========== GUI SETUP ==========
root = tk.Tk()
root.title("WiFi Security Info")
root.geometry("500x420")
root.resizable(False, False)
root.configure(background="cyan")

# Styling
style = ttk.Style()
style.configure("TLabel", font=("Cambria", 11))
style.configure("TButton", font=("Cambria", 11))

frame = ttk.Frame(root, padding=20)
frame.pack(expand=True)

# Fields to show on the GUI
labels = {}
fields = [
    "SSID",
    "Authentication",
    "Cipher",
    "Security Key",
    "Password",
    "Signal Strength",
    "Physical Address",
    "Band"
]

# Create labels for each field
for idx, key in enumerate(fields):
    ttk.Label(frame, text=f"{key}:").grid(row=idx, column=0, sticky="w", pady=5)
    labels[key] = ttk.Label(frame, text="Loading...", foreground="blue")
    labels[key].grid(row=idx, column=1, sticky="w", pady=5)

# Add Buttons: Refresh and Toggle
ttk.Button(frame, text="Refresh", command=update_info).grid(row=len(fields), column=0, columnspan=2, pady=10)
toggle_btn = ttk.Button(frame, text="Show Password", command=toggle_sensitive)
toggle_btn.grid(row=len(fields)+1, column=0, columnspan=2)

# Load data on startup
update_info()

# Run the app
root.mainloop()
