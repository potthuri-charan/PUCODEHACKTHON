import os
import time
import hashlib
import psutil
import shutil
import socket
import yara
import zipfile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import smtplib
from tkinter import Tk, Label, Entry, Button, messagebox
import threading
import csv  

# Constants
RDP_PORT = 3389
EMAIL_FILE = "user_email.txt"
CSV_FILE = "./download.csv"  

# Function to calculate file hash
def calculate_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        return file_hash
    except Exception as e:
        return None

# Function to send email alerts
def send_email_alert(message):
    try:
        if not os.path.exists(EMAIL_FILE):
            print("Email not set. Skipping alert.")
            return
        with open(EMAIL_FILE, 'r') as f:
            receiver_email = f.read().strip()

        sender_email = "potthuricharanpadmasrikhar@gmail.com"
        password = "dbwk eedg xrpw mcni"
        subject = "Ransomware Alert!"

        email_body = f"Subject: {subject}\n\n{message}"
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, email_body)
        print("Alert sent:", message)
    except Exception as e:
        print("Failed to send email alert:", e)

# Popup alert
def show_popup(message):
    Tk().withdraw()
    messagebox.showwarning("Ransomware Defender Alert", message)

# YARA rule scanner using CSV dataset
def scan_with_csv(file_path, hashes_set):
    try:
        file_hash = calculate_hash(file_path)
        if file_hash in hashes_set:
            message = f"Malicious file detected: {file_path}\nHash: {file_hash}"
            print(message)
            send_email_alert(message)
            show_popup(message)
    except Exception as e:
        print(f"Error scanning file with CSV data: {file_path}, Error: {e}")

# Event handler for file system changes
class RansomwareHandler(FileSystemEventHandler):
    def _init_(self, monitored_files, hashes_set):
        self.monitored_files = monitored_files
        self.hashes_set = hashes_set

    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        new_hash = calculate_hash(file_path)
        old_hash = self.monitored_files.get(file_path)

        if old_hash and new_hash != old_hash:
            try:
                # Scan file with CSV hashes for malware detection
                scan_with_csv(file_path, self.hashes_set)

            except Exception as e:
                print(f"Error analyzing file {file_path}: {e}")
        self.monitored_files[file_path] = new_hash

# Monitor running processes for suspicious behavior
def monitor_processes():
    while True:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                # Check if the process has an executable file
                if proc.info["exe"] and proc.info["exe"].endswith(".exe"):
                    # Retrieve connections for the process
                    for conn in proc.connections(kind="inet"):
                        if conn.laddr.port == RDP_PORT:
                            message = f"Process {proc.info['name']} is trying to access RDP port!"
                            print(message)
                            send_email_alert(message)
                            show_popup(message)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        time.sleep(5)

# Initialize monitored files
def initialize_monitored_files(root_directories):
    monitored_files = {}
    for root_dir in root_directories:
        for root, _, files in os.walk(root_dir):
            for file in files:
                file_path = os.path.join(root, file)
                monitored_files[file_path] = calculate_hash(file_path)
    return monitored_files

# GUI for email input
def setup_email():
    def save_email():
        email = email_entry.get().strip()
        if "@" not in email or "." not in email:
            messagebox.showerror("Invalid Email", "Please enter a valid email address.")
            return
        with open(EMAIL_FILE, "w") as f:
            f.write(email)
        messagebox.showinfo("Success", "Email saved successfully!")
        root.destroy()

    root = Tk()
    root.title("Setup Email")
    root.geometry("300x150")

    Label(root, text="Enter your email for alerts:").pack(pady=10)
    email_entry = Entry(root, width=30)
    email_entry.pack(pady=5)
    Button(root, text="Save", command=save_email).pack(pady=10)

    root.mainloop()

# Function to read the CSV file and return a set of hashes
def load_hashes_from_csv(csv_file):
    hashes_set = set()
    try:
        with open(csv_file, mode='r') as f:
            reader = csv.reader(f)
            for row in reader:
                if row:  # Skip empty rows
                    hashes_set.add(row[0].strip())  # Assuming the first column contains the hash values
        print(f"Loaded {len(hashes_set)} hashes from {csv_file}")
    except Exception as e:
        print(f"Error reading CSV file: {e}")
    return hashes_set

# Main function
def main():
    # Load hashes from CSV file
    hashes_set = load_hashes_from_csv(CSV_FILE)

    if not os.path.exists(EMAIL_FILE):
        setup_email()

    # Only include drives that are accessible
    root_directories = []
    for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive_path = f"{drive}:\\"
        if os.path.exists(drive_path):
            try:
                # Try accessing the drive to ensure it's available
                if os.listdir(drive_path):
                    root_directories.append(drive_path)
            except PermissionError:
                print(f"Permission denied for drive {drive_path}")
            except OSError:
                print(f"Error accessing drive {drive_path}")

    print("Initializing file monitoring...")
    monitored_files = initialize_monitored_files(root_directories)
    print("Initialization complete. Starting monitoring...")

    event_handler = RansomwareHandler(monitored_files, hashes_set)
    observer = Observer()
    for root_dir in root_directories:
        try:
            observer.schedule(event_handler, root_dir, recursive=True)
        except FileNotFoundError:
            print(f"Directory not found: {root_dir}")
        except PermissionError:
            print(f"Permission denied: {root_dir}")

    observer.start()

    process_monitor_thread = threading.Thread(target=monitor_processes, daemon=True)
    process_monitor_thread.start()

    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
