
import sys
import socket
import paramiko
import threading
import re
from datetime import datetime
from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import QTimer

# Email settings
SMTP_SERVER = "192.168.18.25"  # Change if using a different provider
SMTP_PORT = 25
EMAIL_SENDER = "info@alliedrec.com.au"
EMAIL_PASSWORD = "Nyepi2017"  # Consider using an App Password
EMAIL_RECIPIENT = "alliedco.bali@gmail.com"

# Router login details
ROUTER_IP = "192.168.103.1"
USERNAME = "admin"
PASSWORD = "Bryan2011"

# Syslog listener settings
UDP_IP = "0.0.0.0"  # Listen on all interfaces
UDP_PORT = 514

# Simulated fetch_sms_details function for this UI
# Function to fetch SMS details from router
def fetch_sms_details(sms_index):
    print(f"🔍 Fetching SMS details for index: {sms_index}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ROUTER_IP, username=USERNAME, password=PASSWORD)

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

class CiscoSMSMonitorApp(QtWidgets.QMainWindow):
    def __init__(self):
        super(CiscoSMSMonitorApp, self).__init__()
        uic.loadUi("combined_sms_monitor.ui", self)

        self.devices = []
        self.sms_logs = []
        self.is_paused = False

        self.addButton.clicked.connect(self.add_device)
        self.refreshButton.clicked.connect(self.load_devices)
        self.pauseButton.clicked.connect(self.toggle_pause)
        self.exportButton.clicked.connect(self.export_to_csv)
        self.smsSearchLineEdit.textChanged.connect(self.filter_sms_logs)

        self.load_devices()
        self.start_syslog_listener()

    def load_devices(self):
        self.devices = [
            {"name": "Router A", "ip": "192.168.1.1", "sim": "628123456789", "apn": "internet.telkomsel", "email": "alerts@domain.com"},
            {"name": "Router B", "ip": "192.168.1.2", "sim": "628223456789", "apn": "3data", "email": "support@x.com"}
        ]
        self.deviceTable.setColumnCount(5)
        self.deviceTable.setHorizontalHeaderLabels(["Device", "IP", "SIM", "APN", "Email"])
        self.deviceTable.setRowCount(len(self.devices))

        for i, d in enumerate(self.devices):
            self.deviceTable.setItem(i, 0, QtWidgets.QTableWidgetItem(d["name"]))
            self.deviceTable.setItem(i, 1, QtWidgets.QTableWidgetItem(d["ip"]))
            self.deviceTable.setItem(i, 2, QtWidgets.QTableWidgetItem(d["sim"]))
            self.deviceTable.setItem(i, 3, QtWidgets.QTableWidgetItem(d["apn"]))
            self.deviceTable.setItem(i, 4, QtWidgets.QTableWidgetItem(d["email"]))

    def add_device(self):
        QtWidgets.QMessageBox.information(self, "Add Device", "Add device functionality coming soon!")

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
        self.smsTable.setColumnCount(5)
        self.smsTable.setHorizontalHeaderLabels(["ID", "Time", "From", "Size", "Message"])
        self.smsTable.setRowCount(len(logs))
        for i, sms in enumerate(logs):
            self.smsTable.setItem(i, 0, QtWidgets.QTableWidgetItem(sms["ID"]))
            self.smsTable.setItem(i, 1, QtWidgets.QTableWidgetItem(sms["Time"]))
            self.smsTable.setItem(i, 2, QtWidgets.QTableWidgetItem(sms["From"]))
            self.smsTable.setItem(i, 3, QtWidgets.QTableWidgetItem(str(sms["Size"])))
            self.smsTable.setItem(i, 4, QtWidgets.QTableWidgetItem(sms["Content"]))

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
