import os
import sys
import socket
import paramiko
import time
import threading
import re
from datetime import datetime
from PyQt5 import QtWidgets, uic
from sms_log_dialog import SMSLogDialog
from PyQt5.QtGui import QMovie
from PyQt5.QtCore import Qt, QSize, QTimer

import mysql.connector
import sip

# No crash – safely register using sip
sip.setapi('QString', 2)
sip.setapi('QVariant', 2)

def resource_path(relative_path):
    """ Get absolute path to resource (works for .exe and dev) """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

class DeviceSettingsDialog(QtWidgets.QDialog):
    def __init__(self, device=None, parent=None):
        super(DeviceSettingsDialog, self).__init__(parent)
        uic.loadUi(resource_path("device_settings_dialog.ui"), self)

        self.device = device
        if device:
            self.nameLineEdit.setText(device["name"])
            self.ipLineEdit.setText(device["ip"])
            self.simLineEdit.setText(device["sim"])
            self.apnLineEdit.setText(device["apn"])
            self.emailLineEdit.setText(device["email"])
        self.saveButton.clicked.connect(self.accept)
        self.cancelButton.clicked.connect(self.reject)

    def get_data(self):
        return {
            "name": self.nameLineEdit.text(),
            "ip": self.ipLineEdit.text(),
            "sim": self.simLineEdit.text(),
            "apn": self.apnLineEdit.text(),
            "email": self.emailLineEdit.text(),
        }

# Email settings
SMTP_SERVER = "192.168.18.25"  # Change if using a different provider
SMTP_PORT = 25
EMAIL_SENDER = "info@alliedrec.com.au"
EMAIL_PASSWORD = "Nyepi2017"  # Consider using an App Password
EMAIL_RECIPIENT = "alliedco.bali@gmail.com"

# Router login details
ROUTER_IPS = "192.168.100.1"
USERNAME = "admin"
PASSWORD = "Bryan2011"

# Syslog listener settings
UDP_IP = "0.0.0.0"  # Listen on all interfaces
UDP_PORT = 514

def load_devices_from_db():
    conn = mysql.connector.connect(
        host="localhost",         # or your server IP
        user="root",
        password="admin1234!",
        database="cisco_sms"
    )
    cursor = conn.cursor()
    cursor.execute("SELECT name, ip, sim, apn, email FROM devices")
    rows = cursor.fetchall()
    conn.close()

    devices = []
    for row in rows:
        devices.append({
            "name": row[0],
            "ip": row[1],
            "sim": row[2],
            "apn": row[3],
            "email": row[4],
            "lastSMS": "",  # You can fetch from another table or update manually
            "signal": 0     # Update this based on monitoring
        })
    return devices

def get_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

def configure_sms_applet_on_cisco(router_ip, username, password):
    eem_script = f"""
        configure terminal
        !
        ! Remove and re-create EEM applet
        no event manager applet SMS_Extract
        event manager applet SMS_Extract
        event syslog pattern "Cellular0/0/0: New SMS received on index ([0-9]+)"
        action 1.0 cli command "enable"
        action 2.0 regexp "index ([0-9]+)" "$_syslog_msg" match sms_index
        action 3.0 cli command "cellular 0/0/0 lte sms view $sms_index"
        action 4.0 regexp "SMS ID: ([0-9]+)" "$_cli_result" match sms_id
        action 5.0 syslog msg "SMS Extracted -> ID: $sms_id"
        exit
        !
        ! Configure remote syslog destination
        logging host {get_ip_address()}
        logging trap informational
        exit
        write memory
    """


    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)

        shell = ssh.invoke_shell()
        time.sleep(1)
        shell.recv(1000)  # Clear initial output

        for line in eem_script.strip().split("\n"):
            shell.send(line.strip() + "\n")
            time.sleep(0.5)

        output = shell.recv(5000).decode()
        print(output)
        ssh.close()
        print(f"EEM applet configured on {router_ip}")
    except Exception as e:
        print(f"Failed to configure EEM on {router_ip}: {e}")


def insert_device_to_db(device):
    conn = mysql.connector.connect(
        host="localhost",         # or your server IP
        user="root",
        password="admin1234!",
        database="cisco_sms"
    )
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO devices (name, ip, sim, apn, email)
        VALUES (%s, %s, %s, %s, %s)
    """, (device["name"], device["ip"], device["sim"], device["apn"], device["email"]))
    conn.commit()
    conn.close()

# Simulated fetch_sms_details function for this UI
# Function to fetch SMS details from router
def fetch_sms_details(router_ip, sms_index):
    print(f"🔍 Fetching SMS details for index: {sms_index}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(router_ip, username=USERNAME, password=PASSWORD)

    command = f"cellular 0/0/0 lte sms view {sms_index}"
    stdin, stdout, stderr = ssh.exec_command(command)
    sms_output = stdout.read().decode()

    ssh.close()

    # Extract SMS details using regex
    sms_id = re.search(r"SMS ID: (\d+)", sms_output)
    sms_time = re.search(r"TIME: ([\d-]+ [\d:]+)", sms_output)
    sms_from = re.search(r"FROM: (\d+)", sms_output)
    sms_size = re.search(r"SIZE: (\d+)", sms_output)
    sms_content_match = re.search(r"SIZE: \d+\s*(.+)", sms_output, re.DOTALL)

    sms_details = {
        "ID": sms_id.group(1) if sms_id else "Unknown",
        "Time": sms_time.group(1) if sms_time else "Unknown",
        "From": sms_from.group(1) if sms_from else "Unknown",
        "Size": sms_size.group(1) if sms_size else "Unknown",
        "Content": sms_content_match.group(1).strip() if sms_content_match else "Unknown",
    }

    print(f"📩 SMS Extracted -> {sms_details}")

    return sms_details

def fetch_all_sms(router_ip):
    import paramiko, time, re

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(router_ip, username=USERNAME, password=PASSWORD, look_for_keys=False, allow_agent=False)

    shell = ssh.invoke_shell()
    time.sleep(1)
    shell.recv(1000)

    shell.send("terminal length 0\n")
    time.sleep(0.5)
    shell.recv(1000)

    shell.send("cellular 0/0/0 lte sms view all\n")
    time.sleep(1)

    output = ""
    while True:
        if shell.recv_ready():
            output += shell.recv(4096).decode(errors="ignore")
            time.sleep(0.2)
        else:
            break

    ssh.close()

    sms_blocks = re.split(r"\n(?=SMS ID:)", output.strip())

    all_sms = []
    for block in sms_blocks:
        sms_id = re.search(r"SMS ID: (\d+)", block)
        sms_time = re.search(r"TIME: ([\d-]+ [\d:]+)", block)
        sms_from = re.search(r"FROM: (\d+)", block)
        sms_size = re.search(r"SIZE: (\d+)", block)
        sms_content_match = re.search(r"SIZE: \d+\s*\n(.+)", block)

        # Skip if any essential field is missing
        if not all([sms_id, sms_time, sms_from, sms_content_match]):
            continue

        # Build only if all required values exist
        sms_details = {
            "ID": sms_id.group(1),
            "Time": sms_time.group(1),
            "From": sms_from.group(1),
            "Size": sms_size.group(1) if sms_size else "0",
            "Content": sms_content_match.group(1).strip(),
        }

        all_sms.append(sms_details)

    return all_sms



class CiscoSMSMonitorApp(QtWidgets.QMainWindow):
    def get_router_name(self, ip):
        for device in self.devices:
            if device["ip"] == ip:
                return device["name"]
        return ip  # fallback to IP if name not found

    def __init__(self):
        super().__init__()
        ui_file = resource_path("combined_sms_monitor.ui")
        uic.loadUi(ui_file, self)

        self.spinner_label = QtWidgets.QLabel(self)
        self.spinner_movie = QMovie(resource_path("spinner.gif"))
        self.spinner_movie.setScaledSize(QSize(100, 100))
        self.spinner_label.setMovie(self.spinner_movie)
        self.spinner_label.setAlignment(Qt.AlignCenter)
        self.spinner_label.setStyleSheet("background-color: rgba(255, 255, 255, 180); border-radius: 10px;")
        self.spinner_label.setVisible(False)
        self.spinner_label.resize(120, 120)
        self.spinner_label.move(self.width()//2 - 60, self.height()//2 - 60)


        self.devices = load_devices_from_db()
        self.sms_logs = []
        self.is_paused = False

        self.addButton.clicked.connect(self.add_device)
        self.refreshButton.clicked.connect(lambda: self.load_devices(self.devices))
        self.searchLineEdit.textChanged.connect(self.filter_devices)
        self.pauseButton.clicked.connect(self.toggle_pause)
        self.exportButton.clicked.connect(self.export_to_csv)
        self.smsSearchLineEdit.textChanged.connect(self.filter_sms_logs)

        self.load_devices(self.devices)
        self.start_syslog_listener()

    def show_spinner(self):
        self.addButton.setEnabled(False)
        self.spinner_label.setVisible(True)
        self.spinner_movie.start()
        QtWidgets.QApplication.processEvents()

    def hide_spinner(self):
        self.spinner_movie.stop()
        self.spinner_label.setVisible(False)
        self.addButton.setEnabled(True)

    def update_devices_and_ui(self, new_devices):
        self.devices = new_devices
        self.load_devices(self.devices)

    def load_devices(self, device_list):
        self.deviceTable.setColumnCount(8)
        self.deviceTable.setHorizontalHeaderLabels(["Device", "IP", "SIM", "APN", "Email", "Last SMS", "Signal", "Actions"])
        self.deviceTable.setRowCount(len(device_list))

        for i, d in enumerate(device_list):
            self.deviceTable.setItem(i, 0, QtWidgets.QTableWidgetItem(d["name"]))
            self.deviceTable.setItem(i, 1, QtWidgets.QTableWidgetItem(d["ip"]))
            self.deviceTable.setItem(i, 2, QtWidgets.QTableWidgetItem(d["sim"]))
            self.deviceTable.setItem(i, 3, QtWidgets.QTableWidgetItem(d["apn"]))
            self.deviceTable.setItem(i, 4, QtWidgets.QTableWidgetItem(d["email"]))
            self.deviceTable.setItem(i, 5, QtWidgets.QTableWidgetItem(d["lastSMS"]))
            self.deviceTable.setItem(i, 6, QtWidgets.QTableWidgetItem("▓" * d["signal"]))

            action_layout = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)

            edit_button = QtWidgets.QPushButton("Edit")
            edit_button.clicked.connect(lambda _, row=i: self.open_settings_dialog(row))
            layout.addWidget(edit_button)

            sms_button = QtWidgets.QPushButton("SMS Logs")
            sms_button.clicked.connect(lambda _, row=i: self.show_sms_log_dialog(row))
            layout.addWidget(sms_button)

            action_layout.setLayout(layout)
            self.deviceTable.setCellWidget(i, 7, action_layout)

    def open_settings_dialog(self, index):
        dialog = DeviceSettingsDialog(device=self.devices[index], parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            self.devices[index] = dialog.get_data()
            self.devices[index]["lastSMS"] = self.devices[index].get("lastSMS", "")
            self.devices[index]["signal"] = self.devices[index].get("signal", 3)
            self.load_devices(self.devices)

    def add_device(self):
        dialog = DeviceSettingsDialog(parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            new_device = dialog.get_data()
            self.show_spinner()

            def background_task():
                try:
                    insert_device_to_db(new_device)
                    configure_sms_applet_on_cisco(
                        router_ip=new_device["ip"],
                        username="admin",
                        password="Bryan2011"
                    )
                    updated_devices = load_devices_from_db()

                    # Safely update UI and self.devices
                    QTimer.singleShot(0, lambda: self.update_devices_and_ui(updated_devices))
                except Exception as e:
                    QTimer.singleShot(0, lambda: QtWidgets.QMessageBox.warning(
                        self, "Error", f"Failed to add device:\n{e}"
                    ))
                finally:
                    QTimer.singleShot(0, self.hide_spinner)

            threading.Thread(target=background_task, daemon=True).start()




    def show_sms_log_dialog(self, index):
        logs = fetch_all_sms(self.devices[index]["ip"])
        dialog = SMSLogDialog(device_name=self.devices[index]["name"], sms_logs=logs, parent=self)
        dialog.exec_()

    def filter_devices(self):
        query = self.searchLineEdit.text().lower()
        filtered = [
            device for device in self.devices
            if query in device["name"].lower() or
               query in device["ip"] or
               query in device["sim"]
        ]
        self.load_devices(filtered)

    def toggle_pause(self):
        self.is_paused = not self.is_paused
        self.pauseButton.setText("Resume" if self.is_paused else "Pause")
        self.statusLabel.setText("⏸️ Paused" if self.is_paused else "🟢 Listening for SMS...")

    def export_to_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export SMS Logs", "", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write("ID,Time,From,Size,Message\n")
            for log in self.sms_logs:
                content = log['Content'].replace('"', '""')
                f.write(f'{log["ID"]},{log["Time"]},{log["From"]},{log["Size"]},"{content}"\n')
        QtWidgets.QMessageBox.information(self, "Export", "SMS logs exported successfully.")

    def filter_sms_logs(self):
        keyword = self.smsSearchLineEdit.text().lower()
        filtered = [sms for sms in self.sms_logs if keyword in sms["Content"].lower() or keyword in sms["From"]]
        self.display_sms_logs(filtered)

    def display_sms_logs(self, logs):
        self.smsTable.setColumnCount(6)
        self.smsTable.setHorizontalHeaderLabels(["Router", "ID", "Time", "From", "Size", "Message"])
        self.smsTable.setRowCount(len(logs))
        for i, sms in enumerate(logs):
            self.smsTable.setItem(i, 0, QtWidgets.QTableWidgetItem(sms.get("Router", "Unknown")))
            self.smsTable.setItem(i, 1, QtWidgets.QTableWidgetItem(sms["ID"]))
            self.smsTable.setItem(i, 2, QtWidgets.QTableWidgetItem(sms["Time"]))
            self.smsTable.setItem(i, 3, QtWidgets.QTableWidgetItem(sms["From"]))
            self.smsTable.setItem(i, 4, QtWidgets.QTableWidgetItem(str(sms["Size"])))
            self.smsTable.setItem(i, 5, QtWidgets.QTableWidgetItem(sms["Content"]))

    def add_sms_log(self, sms):
        self.sms_logs.insert(0, sms)
        self.display_sms_logs(self.sms_logs[:100])

    def start_syslog_listener(self):
        def listen():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 514))
            print("📡 Syslog listener started...")

            while True:
                data, addr = sock.recvfrom(1024)
                if self.is_paused:
                    continue
                message = data.decode("utf-8")
                router_ip = addr[0]
                print(f"🔔 Syslog from {router_ip}: {message.strip()}")

                print(f"📩 Syslog from {addr}: {message}")  # Debugging line

                # Extract SMS index from syslog message
                match = re.search(r"SMS Extracted -> ID: (\d+)", message)  # Adjusted regex pattern
                if match:
                    sms_index = match.group(1)
                    sms = fetch_sms_details(sms_index)
                    sms["Router"] = self.get_router_name(router_ip)
                    self.add_sms_log(sms)
                else:
                    print("⚠️ Pattern not matched.")

        t = threading.Thread(target=listen, daemon=True)
        t.start()

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = CiscoSMSMonitorApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
    
    def display_devices(self, device_list):
        self.deviceTable.setRowCount(len(device_list))
        self.deviceTable.setColumnCount(7)
        self.deviceTable.setHorizontalHeaderLabels(["Device", "IP", "SIM", "APN", "Email", "Signal", "Actions"])

        for i, device in enumerate(device_list):
            self.deviceTable.setItem(i, 0, QtWidgets.QTableWidgetItem(device["name"]))
            self.deviceTable.setItem(i, 1, QtWidgets.QTableWidgetItem(device["ip"]))
            self.deviceTable.setItem(i, 2, QtWidgets.QTableWidgetItem(device["sim"]))
            self.deviceTable.setItem(i, 3, QtWidgets.QTableWidgetItem(device["apn"]))
            self.deviceTable.setItem(i, 4, QtWidgets.QTableWidgetItem(device["email"]))
            self.deviceTable.setItem(i, 5, QtWidgets.QTableWidgetItem("▓" * device.get("signal", 0)))

            action_layout = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)

            edit_button = QtWidgets.QPushButton("Edit")
            edit_button.clicked.connect(lambda _, row=i: self.open_settings_dialog(row))
            layout.addWidget(edit_button)

            sms_button = QtWidgets.QPushButton("SMS Logs")
            sms_button.clicked.connect(lambda _, row=i: self.show_sms_log_dialog(row))
            layout.addWidget(sms_button)

            action_layout.setLayout(layout)
            self.deviceTable.setCellWidget(i, 6, action_layout)

    def open_settings_dialog(self, index):
        dialog = DeviceSettingsDialog(device=self.devices[index], parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            self.devices[index] = dialog.get_data()
            self.devices[index]["lastSMS"] = self.devices[index].get("lastSMS", "")
            self.devices[index]["signal"] = self.devices[index].get("signal", 3)
            self.display_devices(self.devices)
    
    def show_sms_log_dialog(self, index):
        logs = [
            {"id": 2, "time": "25-04-30 11:50:09", "from": "6281335588004", "size": 8, "message": "Yes send"},
            {"id": 3, "time": "25-04-30 12:00:00", "from": "6281112345678", "size": 12, "message": "Hello again!"}
        ]
        dialog = SMSLogDialog(device_name=self.devices[index]["name"], sms_logs=logs, parent=self)
        dialog.exec_()
    