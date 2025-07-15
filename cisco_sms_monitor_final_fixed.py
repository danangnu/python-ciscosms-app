import os
import sys
import socket
import paramiko
import time
import threading
import re
import platform
import subprocess
from datetime import datetime
from PyQt5 import QtWidgets, uic
from sms_log_dialog import SMSLogDialog
from PyQt5.QtGui import QMovie
from PyQt5.QtCore import Qt, QSize, QTimer, QObject, pyqtSignal, QMetaObject, pyqtSlot

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
    
def is_device_online(ip):
    # Determine ping command based on OS
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]

    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output.returncode == 0
    except Exception:
        return False

def load_devices_from_db():
    conn = mysql.connector.connect(
        host="localhost",
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
        ip = row[1]
        online = is_device_online(ip)
        devices.append({
            "name": row[0],
            "ip": ip,
            "sim": row[2],
            "apn": row[3],
            "email": row[4],
            "lastSMS": "",
            "signal": 0,
            "status": "Online" if online else "Offline"
        })
    return devices

def update_device_in_db(device):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="admin1234!",
        database="cisco_sms"
    )
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE devices
        SET sim = %s, apn = %s, email = %s, name = %s
        WHERE ip = %s
    """, (device["sim"], device["apn"], device["email"], device["name"], device["ip"]))
    conn.commit()
    cursor.close()
    conn.close()


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
        host="localhost",
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
    cursor.close()
    conn.close()

def fetch_sms_details(router_ip, sms_index):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(router_ip, username="admin", password="Bryan2011")
    command = f"cellular 0/0/0 lte sms view {sms_index}"
    stdin, stdout, stderr = ssh.exec_command(command)
    sms_output = stdout.read().decode()
    ssh.close()
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
    return sms_details

def create_status_label(status):
    label = QtWidgets.QLabel()
    
    if status == "Online":
        text = '<span style="color: black;">Online </span><span style="color: #34d399; font-size: 20px;">●</span>'
    else:
        text = '<span style="color: black;">Offline </span><span style="color: #f87171; font-size: 20px;">●</span>'

    label.setText(text)
    label.setAlignment(Qt.AlignCenter)
    return label

def fetch_all_sms(router_ip):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(router_ip, username="admin", password="Bryan2011", look_for_keys=False, allow_agent=False)
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
        if not all([sms_id, sms_time, sms_from, sms_content_match]):
            continue
        sms_details = {
            "ID": sms_id.group(1),
            "Time": sms_time.group(1),
            "From": sms_from.group(1),
            "Size": sms_size.group(1) if sms_size else "0",
            "Content": sms_content_match.group(1).strip(),
        }
        all_sms.append(sms_details)
    return all_sms

class SendSMSDialog(QtWidgets.QDialog):
    def __init__(self, device_name, router_ip, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Send SMS via {device_name}")
        self.setFixedSize(300, 200)

        layout = QtWidgets.QVBoxLayout()

        self.to_input = QtWidgets.QLineEdit()
        self.to_input.setPlaceholderText("Recipient Number")
        layout.addWidget(QtWidgets.QLabel("To:"))
        layout.addWidget(self.to_input)

        self.message_input = QtWidgets.QPlainTextEdit()
        self.message_input.setPlaceholderText("Enter your message")
        layout.addWidget(QtWidgets.QLabel("Message:"))
        layout.addWidget(self.message_input)

        send_btn = QtWidgets.QPushButton("Send")
        send_btn.clicked.connect(self.accept)
        layout.addWidget(send_btn)

        self.setLayout(layout)
        self.router_ip = router_ip

    def get_sms_data(self):
        return self.to_input.text(), self.message_input.toPlainText()


class WorkerSignals(QObject):
    finished = pyqtSignal(list)
    def __init__(self, parent=None):
        super().__init__(parent)

class CiscoSMSMonitorApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        ui_file = resource_path("combined_sms_monitor.ui")
        uic.loadUi(ui_file, self)
        self.just_added_device = False
        self.worker_signals = WorkerSignals(self)
        self.worker_signals.finished.connect(self.update_devices_and_ui)
        print("Signal connected!")
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
        QTimer.singleShot(2000, lambda: self.worker_signals.finished.emit(self.devices))
        self.sms_logs = []
        self.is_paused = False

        self.addButton.clicked.connect(self.add_device)
        self.refreshButton.clicked.connect(self.refresh_devices_from_db)
        self.searchLineEdit.textChanged.connect(self.filter_devices)
        self.pauseButton.clicked.connect(self.toggle_pause)
        self.exportButton.clicked.connect(self.export_to_csv)
        self.smsSearchLineEdit.textChanged.connect(self.filter_sms_logs)

        self.load_devices(self.devices)
        self.start_syslog_listener()

    @pyqtSlot(list)
    def emit_finished_signal(self, updated_devices):
        print("[MAIN] emit_finished_signal called")
        self.worker_signals.finished.emit(updated_devices)


    def get_router_name(self, ip):
        for device in self.devices:
            if device["ip"] == ip:
                return device["name"]
        return ip  # fallback to IP if name not found

    def refresh_devices_from_db(self):
        self.devices = load_devices_from_db()
        self.load_devices(self.devices)

    def show_spinner(self):
        self.addButton.setEnabled(False)
        self.spinner_label.setVisible(True)
        self.spinner_movie.start()
        QtWidgets.QApplication.processEvents()

    def hide_spinner(self):
        self.spinner_movie.stop()
        self.spinner_label.setVisible(False)
        self.addButton.setEnabled(True)

    def load_devices(self, device_list):
        print(f"🔄 Loading {len(device_list)} devices into table")
        self.deviceTable.setColumnCount(9)
        self.deviceTable.setHorizontalHeaderLabels([
            "Device", "IP", "SIM", "APN", "Email", "Last SMS", "Signal", "Status", "Actions"
        ])
        self.deviceTable.setRowCount(len(device_list))
        for i, d in enumerate(device_list):
            self.deviceTable.setItem(i, 0, QtWidgets.QTableWidgetItem(d["name"]))
            self.deviceTable.setItem(i, 1, QtWidgets.QTableWidgetItem(d["ip"]))
            self.deviceTable.setItem(i, 2, QtWidgets.QTableWidgetItem(d["sim"]))
            self.deviceTable.setItem(i, 3, QtWidgets.QTableWidgetItem(d["apn"]))
            self.deviceTable.setItem(i, 4, QtWidgets.QTableWidgetItem(d["email"]))
            self.deviceTable.setItem(i, 5, QtWidgets.QTableWidgetItem(d.get("lastSMS", "")))
            self.deviceTable.setItem(i, 6, QtWidgets.QTableWidgetItem("▓" * d.get("signal", 0)))
            status_widget = create_status_label(device_list[i]["status"])
            self.deviceTable.setCellWidget(i, 7, status_widget)

            action_layout = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout()
            layout.setContentsMargins(0, 0, 0, 0)
            edit_button = QtWidgets.QPushButton("Edit")
            edit_button.clicked.connect(lambda _, row=i: self.open_settings_dialog(row))
            layout.addWidget(edit_button)

            sms_button = QtWidgets.QPushButton("SMS Logs")
            sms_button.clicked.connect(lambda _, row=i: self.show_sms_log_dialog(row))
            layout.addWidget(sms_button)

            send_button = QtWidgets.QPushButton("Send SMS")
            send_button.clicked.connect(lambda _, row=i: self.show_send_sms_dialog(row))
            layout.addWidget(send_button)
            
            action_layout.setLayout(layout)
            self.deviceTable.setCellWidget(i, 8, action_layout)

    def open_settings_dialog(self, index):
        device = self.devices[index]
        dialog = DeviceSettingsDialog(device=device, parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            updated_data = dialog.get_data()

            # Merge back to current device (keep IP for identification)
            updated_data["ip"] = device["ip"]
            update_device_in_db(updated_data)

            # Reload device list
            self.devices = load_devices_from_db()
            self.load_devices(self.devices)
            QtWidgets.QMessageBox.information(self, "Success", "Device updated successfully.")


    def add_device(self):
        dialog = DeviceSettingsDialog(parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            new_device = dialog.get_data()
            self.show_spinner()
            self.just_added_device = True  # <-- set flag
            
            def background_task():
                try:
                    insert_device_to_db(new_device)
                    configure_sms_applet_on_cisco(
                        router_ip=new_device["ip"],
                        username="admin",
                        password="Bryan2011"
                    )
                    time.sleep(3)
                    updated_devices = load_devices_from_db()
                    print("[BG] Emitting finished signal (via QMetaObject)")
                    QMetaObject.invokeMethod(
                        self,
                        "emit_finished_signal",
                        Qt.QueuedConnection,
                        (updated_devices,)
                    )
                except Exception as e:
                    QMetaObject.invokeMethod(
                        self,
                        "emit_finished_signal",
                        Qt.QueuedConnection,
                        ([],)
                    )
                    QTimer.singleShot(0, lambda: QtWidgets.QMessageBox.warning(
                        self, "Error", f"Failed to add device:\n{e}"
                    ))
                finally:
                    QTimer.singleShot(0, self.hide_spinner)

            threading.Thread(target=background_task, daemon=True).start()


    def update_devices_and_ui(self, updated_devices):
        print("✅ SLOT CALLED WITH DATA:", updated_devices)
        self.devices = updated_devices
        self.load_devices(self.devices)
        print("✅ UI updated with new devices.")
        if self.just_added_device:
            QtWidgets.QMessageBox.information(self, "Success", "Device added successfully and table refreshed!")
            # Optionally, you could trigger another callback here
            # self.refresh_devices_from_db()
            self.just_added_device = False  # reset flag

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

    def send_sms(self, router_ip, username, password, recipient, message):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(router_ip, username=username, password=password)

            command = f'cellular 0/0/0 lte sms send {recipient} "{message}"'
            print(f"📤 Sending SMS: {command}")
            ssh.exec_command(command)
            ssh.close()

            QtWidgets.QMessageBox.information(self, "Success", f"SMS sent to {recipient}")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to send SMS:\n{e}")

    def add_sms_log(self, sms):
        self.sms_logs.insert(0, sms)
        self.display_sms_logs(self.sms_logs[:100])

    def show_send_sms_dialog(self, index):
        device = self.devices[index]
        dialog = SendSMSDialog(device_name=device["name"], router_ip=device["ip"], parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            to_number, message = dialog.get_sms_data()
            self.send_sms(device["ip"], "admin", "Bryan2011", to_number, message)

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
                print(f"📩 Syslog from {addr}: {message}")
                match = re.search(r"SMS Extracted -> ID: (\d+)", message)
                if match:
                    sms_index = match.group(1)
                    sms = fetch_sms_details(router_ip, sms_index)
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
