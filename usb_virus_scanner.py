import json
import tkinter as tk
from tkinter import messagebox, ttk
import os
import subprocess
import smtplib
from email.mime.text import MIMEText
import yara
import threading
import ssl

# إعدادات البريد الإلكتروني
EMAIL_ENABLED = True
EMAIL_FROM = "your_email@example.com"
EMAIL_TO = "recipient@example.com"
EMAIL_PASSWORD = "your_password"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 465

# تحميل معلومات الفيروسات من ملف JSON
with open('virus_info.json', 'r') as file:
    virus_info = json.load(file)

def send_email(subject, body):
    if not EMAIL_ENABLED:
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, context=context) as server:
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

def scan_drive(drive_path, progress_var):
    result = subprocess.run(['clamscan', '-r', drive_path], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    return output

def analyze_file_behavior(file_path):
    rules = yara.compile(filepath='rules.yar')
    matches = rules.match(file_path)
    return matches

def handle_threat(file_path, threat_name):
    def delete_file():
        try:
            os.remove(file_path)
            result_text.insert(tk.END, f"File {file_path} deleted successfully.\n")
        except Exception as e:
            result_text.insert(tk.END, f"Failed to delete {file_path}: {e}\n")
        threat_window.destroy()

    def quarantine_file():
        quarantine_dir = os.path.join(os.path.dirname(file_path), "quarantine")
        if not os.path.exists(quarantine_dir):
            os.makedirs(quarantine_dir)
        try:
            os.rename(file_path, os.path.join(quarantine_dir, os.path.basename(file_path)))
            result_text.insert(tk.END, f"File {file_path} moved to quarantine.\n")
        except Exception as e:
            result_text.insert(tk.END, f"Failed to quarantine {file_path}: {e}\n")
        threat_window.destroy()

    def ignore_threat():
        result_text.insert(tk.END, f"Ignored threat in file {file_path}.\n")
        threat_window.destroy()

    threat_window = tk.Toplevel(app)
    threat_window.title("Threat Detected")

    virus_name = virus_info.get(threat_name, {}).get("name", threat_name)
    virus_description = virus_info.get(threat_name, {}).get("description", "No description available.")
    tk.Label(threat_window, text=f"Threat detected in file: {file_path}").pack(pady=10)
    tk.Label(threat_window, text=f"Virus Name: {virus_name}").pack(pady=5)
    tk.Label(threat_window, text=f"Description: {virus_description}").pack(pady=5)
    tk.Button(threat_window, text="Delete", command=delete_file).pack(side=tk.LEFT, padx=10, pady=10)
    tk.Button(threat_window, text="Quarantine", command=quarantine_file).pack(side=tk.LEFT, padx=10, pady=10)
    tk.Button(threat_window, text="Ignore", command=ignore_threat).pack(side=tk.LEFT, padx=10, pady=10)

def start_scan():
    drives = get_external_drives()
    if not drives:
        messagebox.showinfo("Information", "No external drives found.")
        return

    for drive in drives:
        result_text.insert(tk.END, f"Scanning {drive}...\n")
        app.update_idletasks()
        scan_result = scan_drive(drive, progress_var)

        files_to_scan = [os.path.join(root, file) for root, _, files in os.walk(drive) for file in files]
        for file in files_to_scan:
            behavior_matches = analyze_file_behavior(file)
            if behavior_matches:
                result_text.insert(tk.END, f"Suspicious behavior detected in {file}!\n{behavior_matches}\n")
                handle_threat(file, behavior_matches[0].rule)

        if "FOUND" in scan_result:
            for line in scan_result.splitlines():
                if "FOUND" in line:
                    file_path, virus_name = line.split(":")[:2]
                    virus_name = virus_name.split()[0]  # الحصول على اسم الفيروس فقط
                    result_text.insert(tk.END, f"Virus detected on {drive}: {virus_name}\n{scan_result}\n")
                    handle_threat(file_path.strip(), virus_name)
                    send_email("Virus Detected", f"Virus detected on {drive}: {virus_name}\n{scan_result}")
        else:
            result_text.insert(tk.END, f"No viruses found on {drive}. Drive is safe to use.\n")

        save_scan_results(drive, scan_result)
        progress_var.set(0)
        app.update_idletasks()

def get_external_drives():
    drives = [os.path.join('/media/', drive) for drive in os.listdir('/media/') if os.path.ismount(os.path.join('/media/', drive))]
    return drives

def save_scan_results(drive, scan_result):
    with open(f"{drive.replace('/', '_')}_scan_results.txt", "w") as file:
        file.write(scan_result)

def update_virus_definitions():
    result_text.insert(tk.END, "Updating virus definitions...\n")
    app.update_idletasks()
    result = subprocess.run(['sudo', 'freshclam'], stdout=subprocess.PIPE)
    output = result.stdout.decode()
    result_text.insert(tk.END, output + "\n")
    messagebox.showinfo("Update Complete", "Virus definitions updated successfully.")

def start_scan_thread():
    scan_thread = threading.Thread(target=start_scan)
    scan_thread.start()

app = tk.Tk()
app.title("USB Virus Scanner")

frame = tk.Frame(app)
frame.pack(padx=10, pady=10)

scan_button = tk.Button(frame, text="Start Scan", command=start_scan_thread)
scan_button.pack(side=tk.LEFT, padx=5)

update_button = tk.Button(frame, text="Update Definitions", command=update_virus_definitions)
update_button.pack(side=tk.LEFT, padx=5)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(frame, variable=progress_var, maximum=100)
progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

result_text = tk.Text(app, height=20, width=80)
result_text.pack(padx=10, pady=10)

app.mainloop()
