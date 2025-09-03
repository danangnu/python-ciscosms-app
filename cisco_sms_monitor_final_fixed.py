import os
import sys
import socket
import paramiko
import time
import threading
import re
import platform
import subprocess
import traceback
import json
import smtplib
from cryptography.fernet import Fernet
from datetime import datetime
from PyQt5 import QtWidgets, uic
from sms_log_dialog import SMSLogDialog
from PyQt5.QtGui import QMovie, QIcon
from PyQt5.QtCore import Qt, QSize, QTimer, QObject, pyqtSignal, QMetaObject, pyqtSlot
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QHBoxLayout, QLabel, QToolButton, QMenu, QAction, QSizePolicy
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from PyQt5.QtWidgets import QMainWindow
from PyQt5 import QtCore
from datetime import datetime
import traceback

import mysql.connector
import sip

# No crash – safely register using sip
sip.setapi('QString', 2)
sip.setapi('QVariant', 2)

# Email settings
SMTP_SERVER = "192.168.18.25"  # Change if using a different provider
SMTP_PORT = 25
EMAIL_SENDER = "info@alliedrec.com.au"
EMAIL_PASSWORD = "Nyepi2017"  # Consider using an App Password

def resource_path(relative_path):
    """ Get absolute path to resource (works for .exe and dev) """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

FERNET_KEY = b"hZtFdYoCGy2E68Fz46zqFbW4NHnSLmP4F78w_BV9mN4="
fernet = Fernet(FERNET_KEY)

def encrypt_password(password):
    return fernet.encrypt(password.encode())

def decrypt_password(encrypted):
    return fernet.decrypt(encrypted).decode()

def get_db_config():
    try:
        with open("db_config.json", "r") as f:
            config = json.load(f)
            return {
                "host": config.get("host"),
                "port": config.get("port"),
                "user": config.get("user"),
                "password": config.get("password"),
                "database": config.get("database")
            }
    except Exception as e:
        print(f"⚠️ Failed to read DB config: {e}")
        return None


def get_db_config_ti():
    try:
        with open("db_config.json", "r") as f:
            config = json.load(f)
            return {
                "host": config.get("host"),
                "port": config.get("port"),
                "user": config.get("user"),
                "password": config.get("password"),
                "database": config.get("database_trackit")
            }
    except Exception as e:
        print(f"⚠️ Failed to read DB config: {e}")
        return None

def get_ssh_credentials():
    try:
        db_config = get_db_config()
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM user_ssh ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row:
            return row[0], decrypt_password(row[1])

    except Exception as e:
        print(f"⚠️ Failed to load SSH credentials: {e}")
        return None, None
    
def get_email_profiles():
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, profile_name, smtp_server, smtp_port, sender_email, sender_password, security, is_default
        FROM email_settings ORDER BY is_default DESC, profile_name ASC
    """)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def get_default_email_profile():
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, profile_name, smtp_server, smtp_port, sender_email, sender_password, security, is_default
        FROM email_settings ORDER BY is_default DESC, profile_name ASC LIMIT 1
    """)
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

def upsert_email_profile(profile):
    """
    profile dict: {id (optional), profile_name, smtp_server, smtp_port, sender_email,
                   sender_password, security, is_default(bool)}
    """
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()

    # If setting default, unset others
    if profile.get("is_default"):
        cur.execute("UPDATE email_settings SET is_default = 0")

    if profile.get("id"):
        cur.execute("""
            UPDATE email_settings
               SET profile_name=%s, smtp_server=%s, smtp_port=%s,
                   sender_email=%s, sender_password=%s, security=%s, is_default=%s
             WHERE id=%s
        """, (profile["profile_name"], profile["smtp_server"], int(profile["smtp_port"]),
              profile["sender_email"], profile["sender_password"], profile["security"],
              1 if profile.get("is_default") else 0, int(profile["id"])))
    else:
        cur.execute("""
            INSERT INTO email_settings
            (profile_name, smtp_server, smtp_port, sender_email, sender_password, security, is_default)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (profile["profile_name"], profile["smtp_server"], int(profile["smtp_port"]),
              profile["sender_email"], profile["sender_password"], profile["security"],
              1 if profile.get("is_default") else 0))

    conn.commit()
    cur.close()
    conn.close()

def delete_email_profile(profile_id):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute("DELETE FROM email_settings WHERE id=%s", (int(profile_id),))
    conn.commit()
    cur.close()
    conn.close()

def get_email_config_from_db():
    """Retrieve SMTP and sender details from database."""
    try:
        db_config = get_db_config()
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Example: assuming your table is `email_config`
        cursor.execute("""
            SELECT smtp_server, smtp_port, smtp_user, smtp_password, sender_email
            FROM email_config
            WHERE active = 1
            LIMIT 1
        """)
        config = cursor.fetchone()

        cursor.close()
        conn.close()
        return config

    except Exception as e:
        print(f"❌ Error loading email config from DB: {e}")
        return None
    
def send_email(sms_details, emailTo):
    """Send an email with SMS details using config loaded from database."""
    try:
        config = get_email_config_from_db()
        if not config:
            print("❌ No email configuration found in database.")
            return

        msg = MIMEMultipart()
        msg["From"] = config["sender_email"]
        msg["To"] = emailTo
        msg["Subject"] = f"New SMS Received from {sms_details['From']}"

        body = f"""
            📩 **New SMS Received**
            --------------------------------------
            🆔 ID: {sms_details['ID']}
            ⏰ Time: {sms_details['Time']}
            📞 From: {sms_details['From']}
            📏 Size: {sms_details['Size']}
            📜 Message: 
            {sms_details['Content']}
            --------------------------------------
            """

        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(config["smtp_server"], config["smtp_port"])
        
        # If SMTP requires login
        if config["smtp_user"] and config["smtp_password"]:
            server.login(config["smtp_user"], config["smtp_password"])
        
        server.sendmail(config["sender_email"], emailTo, msg.as_string())
        server.quit()

        print("✅ Email notification sent successfully!")

    except Exception as e:
        print(f"❌ Failed to send email: {e}")

class LoadingSpinner(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background-color: rgba(255, 255, 255, 180);")  # Optional dim

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        self.label = QLabel()
        self.label.setAlignment(Qt.AlignCenter)
        self.movie = QMovie(resource_path("spinner.gif"))  # Your spinner GIF file
        self.movie.setScaledSize(QSize(64, 64))
        self.label.setMovie(self.movie)
        layout.addWidget(self.label)

        self.setVisible(False)

    def start(self):
        self.setVisible(True)
        self.movie.start()

    def stop(self):
        self.setVisible(False)
        self.movie.stop()

class DetectSignals(QObject):
    apnDetected = pyqtSignal(str)
    gatewayDetected = pyqtSignal(str)
    detectFailed = pyqtSignal(str)

class DeviceSettingsDialog(QtWidgets.QDialog):
    def __init__(self, device=None, parent=None):
        super(DeviceSettingsDialog, self).__init__(parent)
        uic.loadUi(resource_path("device_settings_dialog.ui"), self)

        self.detectSignals = DetectSignals()
        self.detectSignals.apnDetected.connect(self.on_apn_detected)
        self.detectSignals.gatewayDetected.connect(self.on_gateway_detected)
        self.detectSignals.detectFailed.connect(self.on_apn_failed)

        self.overlay = QtWidgets.QWidget(self)
        self.overlay.setStyleSheet("background: rgba(255, 255, 255, 0.7);")
        self.overlay.hide()

        # Fill entire dialog
        self.overlay.setGeometry(self.rect())
        self.overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)

        self.overlaySpinner = LoadingSpinner(self.overlay)
        self.overlaySpinner.setFixedSize(80, 80)
        self.overlaySpinner.setGeometry(
            self.overlay.width() // 2 - 40,
            self.overlay.height() // 2 - 40,
            80,
            80
        )

        # Same for gateway detect
        self.gatewaySpinner = LoadingSpinner(self)

        # Add Detect button next to Gateway field
        self.detectGatewayButton = QPushButton("Detect")
        getway_row_layout = QHBoxLayout()
        getway_row_layout.addWidget(self.gatewayLineEdit)
        getway_row_layout.addWidget(self.detectGatewayButton)
        getway_row_layout.addWidget(self.gatewaySpinner)

        # Add Detect button next to APN field
        self.detectApnButton = QPushButton("Detect")
        apn_row_layout = QHBoxLayout()
        apn_row_layout.addWidget(self.apnLineEdit)
        apn_row_layout.addWidget(self.detectApnButton)

        self.resizeEvent = self.resizeEvento  # Override resize event to update overlay

        # Replace the widget in the layout (4th item in the vertical layout, index = 3)
        layout: QtWidgets.QVBoxLayout = self.layout()
        layout.insertLayout(2, getway_row_layout)  # Index 2 = after IP input
        layout.insertLayout(3, apn_row_layout)  # Index 3 = after SIM input

        # Connect detection logic
        self.detectApnButton.clicked.connect(self.handle_detect_apn)
        self.detectGatewayButton.clicked.connect(self.handle_detect_gateway)

        # Set existing fields
        self.device = device
        if device:
            self.nameLineEdit.setText(device["name"])
            self.ipLineEdit.setText(device["ip"])
            self.gatewayLineEdit.setText(device["gateway"])
            self.simLineEdit.setText(device["sim"])
            self.apnLineEdit.setText(device["apn"])
            self.emailLineEdit.setText(device["email"])

        self.saveButton.clicked.connect(self.accept)
        self.cancelButton.clicked.connect(self.reject)

    def resizeEvento(self, event):
        super().resizeEvent(event)
        self.overlay.setGeometry(self.rect())
        self.overlaySpinner.setGeometry(
            self.overlay.width() // 2 - 40,
            self.overlay.height() // 2 - 40,
            80,
            80
        )



    def get_data(self):
        return {
            "name": self.nameLineEdit.text(),
            "ip": self.ipLineEdit.text(),
            "gateway": self.gatewayLineEdit.text(),
            "sim": self.simLineEdit.text(),
            "apn": self.apnLineEdit.text(),
            "email": self.emailLineEdit.text(),
        }
    
    def handle_detect_apn(self):
        ip = self.ipLineEdit.text()
        if not ip:
            QtWidgets.QMessageBox.warning(self, "Missing IP", "Please enter the router IP first.")
            return

        self.overlay.show()
        self.overlaySpinner.start()  # Spinner should be defined as LoadingSpinner

        def run():
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                username, password = get_ssh_credentials()
                ssh.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)

                stdin, stdout, stderr = ssh.exec_command("show cellular 0/0/0 profile")
                output = stdout.read().decode()
                ssh.close()

                match = re.search(r"Profile 1 = ACTIVE.*?APN\) = ([^\s]+)", output, re.DOTALL)
                if match:
                    apn = match.group(1)
                    self.detectSignals.apnDetected.emit(apn)
                else:
                    self.detectSignals.detectFailed.emit("Could not detect APN in the output.")

            except Exception as e:
                self.detectSignals.detectFailed.emit(str(e))

        threading.Thread(target=run, daemon=True).start()

    def on_apn_detected(self, apn):
        self.apnLineEdit.setText(apn)
        self.overlaySpinner.stop()
        self.overlay.hide()
        QtWidgets.QMessageBox.information(self, "APN Detected", f"Detected APN: {apn}")

    def on_gateway_detected(self, gateway):
        self.gatewayLineEdit.setText(gateway)
        self.overlaySpinner.stop()
        self.overlay.hide()
        QtWidgets.QMessageBox.information(self, "Gateway Detected", f"Detected Gateway: {gateway}")

    def on_apn_failed(self, message):
        self.overlaySpinner.stop()
        self.overlay.hide()
        QtWidgets.QMessageBox.warning(self, "Detection Failed", message)

    def handle_detect_gateway(self):
        ip = self.ipLineEdit.text().strip()
        if not ip:
            QtWidgets.QMessageBox.warning(self, "Missing IP", "Please enter the router IP first.")
            return

        self.overlay.show()
        self.overlaySpinner.start()

        def run():
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                username, password = get_ssh_credentials()
                ssh.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)

                stdin, stdout, stderr = ssh.exec_command("show running-config | include ip route")
                output = stdout.read().decode()
                ssh.close()

                gateway = None
                ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

                for line in output.splitlines():
                    if line.startswith("ip route 0.0.0.0 0.0.0.0") and "track" in line:
                        parts = line.split()
                        if len(parts) >= 5 and ipv4_pattern.match(parts[4]):
                            gateway = parts[4]
                            break

                if gateway:
                    self.detectSignals.gatewayDetected.emit(gateway)
                else:
                    self.detectSignals.detectFailed.emit("Could not detect gateway (only IP-based next-hop is supported).")

            except Exception as e:
                self.detectSignals.detectFailed.emit(str(e))

        threading.Thread(target=run, daemon=True).start()


    
def is_device_online(ip):
    # Determine ping command based on OS
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]

    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output.returncode == 0
    except Exception:
        return False

# Fast, SSH-relevant reachability check (better than ping in many networks)
def is_device_online(ip: str, port: int = 22, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

# More reliable local IP (avoid 127.* from gethostbyname(hostname))
def get_ip_address() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

_ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def is_device_register(ip: str, *, timeout: int = 8) -> bool:
    """
    True if router 'ip' has our syslog host configured (logging host <our_ip>).
    - Fast-fails if device is offline or creds missing.
    - Uses tight timeouts to avoid UI stalls.
    """
    # 1) Don’t attempt SSH if it’s not even reachable
    if not is_device_online(ip):
        return False

    username, password = get_ssh_credentials()
    if not username or not password:
        print("⚠️ No SSH credentials available.")
        return False

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            ip,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )

        # Only fetch lines that matter; avoid pagination issues and big outputs
        cmd = r"show running-config | include ^logging host "
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode(errors="ignore")
    except Exception as e:
        print(f"⚠️ is_device_register error for {ip}: {e}")
        return False
    finally:
        try:
            ssh.close()
        except Exception:
            pass

    # 2) Extract configured logging hosts (IPv4) from the lines
    hosts = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("logging host"):
            continue
        m = _ipv4_re.search(line)
        if m:
            hosts.append(m.group(0))

    # 3) Compare against our real local IP
    my_ip = get_ip_address()
    return my_ip in hosts


   

def load_devices_from_db():
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    
    cursor = conn.cursor()
    cursor.execute("SELECT name, ip, gateway, sim, apn, email, id FROM devices")
    rows = cursor.fetchall()
    conn.close()

    devices = []
    for row in rows:
        ip = row[1]
        online = is_device_online(ip)
        register = is_device_register(ip) if online else False
        status = "Offline" if not online else ("Not Register" if not register else "Online")
        devices.append({
            "name": row[0],
            "ip": ip,
            "gateway": row[2],
            "sim": row[3],
            "apn": row[4],
            "email": row[5],
            "lastSMS": "",
            "signal": 0,
            "status": status,
            "id": row[6]
        })
    return devices

def is_phone_number(s: str) -> bool:
    # Boleh diawali +, lalu 7–15 digit
    return bool(re.fullmatch(r"\+?\d{7,15}", s))

def is_hex_string(s: str) -> bool:
    try:
        int(s, 16)  # coba convert ke integer basis 16
        return len(s) % 2 == 0  # panjang harus genap (tiap 2 char = 1 byte)
    except ValueError:
        return False
def semi_octet_decode(hexstr: str) -> str:
    """Decode nomor telp dari semi-octet swap"""
    digits = ""
    for i in range(0, len(hexstr), 2):
        digits += hexstr[i+1] + hexstr[i]
    return digits.rstrip("F")  # remove padding F

def gsm7_decode(hexstr: str) -> str:
    """Decode GSM7 (7-bit default alphabet)"""
    bits = ""
    for i in range(0, len(hexstr), 2):
        bits += bin(int(hexstr[i:i+2], 16))[2:].zfill(8)[::-1]  # little-endian per octet
    
    septets = [bits[i:i+7][::-1] for i in range(0, len(bits), 7)]
    septets = [s for s in septets if len(s) == 7]  

    decoded = ""
    for s in septets:
        val = int(s, 2)
        if 32 <= val <= 126:
            decoded += chr(val)
        else:
            decoded += "?"  # fallback
    return decoded.strip("?")

def normalize_sender(sender: str) -> str:
    """
    Normalisasi pengirim SMS dari Cisco.
    Bisa nomor telp (614xxxx) atau brand name (PIZZAHUT).
    """
    # case 1: sudah nomor telp
    if re.fullmatch(r"\+?\d{6,15}", sender):
        return sender

    # case 2: hex string
    if re.fullmatch(r"[0-9A-Fa-f]+", sender):
        try:
            # coba decode semi-octet → nomor
            num = semi_octet_decode(sender)
            if re.fullmatch(r"\d{6,15}", num):
                return num

            # kalau bukan nomor → coba decode ke GSM7 → brand
            text = gsm7_decode(sender)
            return text if text else sender
        except Exception:
            return sender

    return sender

def gsm7_unpack(hexstr):
    # 1. Swap semi-octets (contoh: "0D" -> "D0")
    swapped = "".join([hexstr[i+1] + hexstr[i] for i in range(0, len(hexstr), 2)])
    data = bytes.fromhex(swapped)

    # 2. GSM 7-bit unpacking
    septets = []
    carry = 0
    carry_bits = 0
    for b in data:
        val = ((b << carry_bits) & 0x7F) | carry
        septets.append(val)
        carry = b >> (7 - carry_bits)
        carry_bits += 1
        if carry_bits == 7:
            septets.append(carry)
            carry = 0
            carry_bits = 0

    # 3. Convert septets to text
    text = "".join(chr(s) for s in septets if 32 <= s <= 126)
    return text

def get_all_sms(ip):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username, password = get_ssh_credentials()
    ssh.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)

    stdin, stdout, stderr = ssh.exec_command("cellular 0/0/0 lte sms view all")
    sms_list_output = stdout.read().decode()
    ssh.close()
    return sms_list_output





def parse_sms(raw_output):
    sms_blocks = raw_output.strip().split("--------------------------------------------------------------------------------")
    sms_list = []

    for block in sms_blocks:
        if not block.strip():
            continue

        sms = {}
        for line in block.strip().splitlines():
            if line.startswith("SMS ID:"):
                sms["ID"] = int(line.replace("SMS ID:", "").strip())
            elif line.startswith("TIME:"):
                raw_time = line.replace("TIME:", "").strip()
                sms_time = datetime.strptime(raw_time, "%y-%m-%d %H:%M:%S")  
                sms["Time"] = sms_time
            elif line.startswith("FROM:"):
                raw = line.replace("FROM:", "").strip()
                if is_phone_number(raw):
                    smsFrom = raw
                    if raw.startswith("61"):
                        smsFrom = "0" + raw[2:]   # ubah ke format lokal
                elif is_hex_string(raw):
                    smsFrom = gsm7_unpack(raw)  # butuh fungsi decode PDU
                else:
                    smsFrom = raw
                sms["From"] = smsFrom
                sms["CiscoFrom"] = raw
            elif line.startswith("SIZE:"):
                sms["Size"] = int(line.replace("SIZE:", "").strip())
            else:
                # anggap sisanya adalah pesan SMS
                sms["Message"] = sms.get("Message", "") + " " + line.strip()
        sms_list.append(sms)
    return sms_list

def get_new_sms_by_time(ip, last_time):
    raw = get_all_sms(ip)
    all_sms = parse_sms(raw)

    # Ambil SMS yang lebih baru dari last_time
    new_sms = [sms for sms in all_sms if sms["Time"] > last_time]
    return new_sms

def save_sms_to_db(sms_list, device):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)

    cursor = conn.cursor()
    sql = """
    INSERT IGNORE INTO sms_logs (dates, sms_from, cisco_from, size, message, devices_id)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    for sms in sms_list:
        cursor.execute(sql, (sms["Time"], sms["From"], sms["CiscoFrom"], sms["Size"], sms["Message"], device["id"]))
    conn.commit()
    cursor.close()

    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM email_notification LIMIT 1")
    row = cursor.fetchone()  # Ambil 1 baris
    if row:  # pastikan ada data
        subject = row[1]  # kolom 2
        email   = row[2]  # kolom 3
        content = row[3]  # kolom 4
    else:
        subject = email = content = None
    conn.close()

    db_config = get_db_config_ti()
    conn = mysql.connector.connect(**db_config)
    now = datetime.now()
    cursor = conn.cursor()
    sql = """
    INSERT INTO logbulkmail(dates, times, sendto, mailsubject, mailcontent, mailstatus, mailtype, cc, spoofas, spoofname, attachment) 
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    for sms in sms_list:
        mailcontent = (
            f"{content}<br />---------<br />From: {sms['From']}<br />"
            f"Received: {sms['Time']}<br />SIM Detail: {device['name']} - {device['sim']}<br />"
            f"Message: {sms['Message']}"
        )
        device["name"] + " - " + device["sim"] + "<br />" + "Message: " + sms["Message"]
        emailReceive = sms["From"] + "@alliedsms.com.au"
        
        cursor.execute(sql, (now.date(), now.strftime("%I:%M:%S %p"), email, subject + " - " +  emailReceive, mailcontent, "Queue In Database", "Email", 1, emailReceive, emailReceive, 0))
    conn.commit()
    cursor.close()


def fetch_from_all_devices(devices):
    for device in devices:
        db_config = get_db_config()
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(dates) FROM sms_logs WHERE devices_id=%s", (device["id"],))
        # Ambil last time per device
        last_time_str = cursor.fetchone()[0] or "2000-01-01 00:00:00"
        conn.close()

        if last_time_str == "2000-01-01 00:00:00":
            last_time = datetime.strptime(last_time_str, "%Y-%m-%d %H:%M:%S")
        else:
            last_time = last_time_str

        new_sms = get_new_sms_by_time(device["ip"], last_time)
        if new_sms:
            save_sms_to_db(new_sms, device)
            print(f"✅ {len(new_sms)} SMS baru dari {device['ip']} disimpan")
        
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT `devices`.name, sms_logs.`dates`, sms_logs.`sms_from`, sms_logs.`message` FROM devices INNER JOIN sms_logs ON sms_logs.`devices_id` = devices.`id`")
    smsList = cursor.fetchall()
    # Ambil last time per device
    conn.close()

    return smsList


def update_device_in_db(device):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE devices
        SET sim = %s, apn = %s, email = %s, name = %s, gateway = %s
        WHERE ip = %s
    """, (device["sim"], device["apn"], device["email"], device["name"], device["gateway"], device["ip"]))
    conn.commit()
    cursor.close()
    conn.close()

def get_email_by_router_ip(router_ip):
    """
    Fetch email for the given router_ip from the devices table.
    """
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT email
        FROM devices
        WHERE ip = %s
    """, (router_ip,))

    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return result[0] if result else None


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
        action 1.0 cli command "enable"
        action 2.0 regexp "index ([0-9]+)" "$_syslog_msg" match sms_index
        action 3.0 cli command "cellular 0/0/0 lte sms view $sms_index"
        action 4.0 syslog msg "SMS Extracted -> ID: $sms_index"
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

def delete_device_from_db(device_id):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE id = %s", (device_id,))
    conn.commit()
    cursor.close()
    conn.close()


def insert_device_to_db(device):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO devices (name, ip, gateway, sim, apn, email)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (device["name"], device["ip"], device["gateway"], device["sim"], device["apn"], device["email"]))
    conn.commit()
    cursor.close()
    conn.close()

def extract_sms_content(sms_text: str) -> str:
    lines = sms_text.strip().splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("SIZE:"):
            # Return the line after 'SIZE:' (should be the content)
            if i + 1 < len(lines):
                return lines[i + 1].strip().strip('"')
    return ""

def fetch_last_sms(ip):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        username, password = get_ssh_credentials()
        ssh.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)

        # Get all SMS
        stdin, stdout, stderr = ssh.exec_command("cellular 0/0/0 lte sms view all")
        sms_list_output = stdout.read().decode()
        ssh.close()
        # Extract SMS indices
        index_matches = re.findall(r'SMS ID: (\d+)', sms_list_output)
        if not index_matches:
            return "No SMS"

        last_index = max(map(int, index_matches))

        # Get the latest SMS
        ssh.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        cmd = f"cellular 0/0/0 lte sms view {last_index}"
        stdin, stdout, stderr = ssh.exec_command(cmd)
        sms_output = stdout.read().decode()
        ssh.close()

        # Extract message content (optional: truncate if too long)
        msg_match = extract_sms_content(sms_output)
        return msg_match

    except Exception as e:
        return f"Error: {str(e)}"
        traceback.print_exc()

def fetch_sms_details(router_ip, sms_index):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username, password = get_ssh_credentials()
    ssh.connect(router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)

    command = f"cellular 0/0/0 lte sms view {sms_index}"
    stdin, stdout, stderr = ssh.exec_command(command)
    sms_output = stdout.read().decode()
    ssh.close()

    # Debug: log raw output in case parsing fails
    print(f"📩 Raw SMS output:\n{sms_output}")

    sms_id = re.search(r"SMS ID: (\d+)", sms_output)
    sms_time = re.search(r"TIME: ([\d-]+ [\d:]+)", sms_output)
    sms_from = re.search(r"FROM: (\d+)", sms_output)
    sms_size = re.search(r"SIZE: (\d+)", sms_output)
    sms_content_match = re.search(r"SIZE: \d+\s*(.+)", sms_output, re.DOTALL)

    if not all([sms_id, sms_time, sms_from, sms_size, sms_content_match]):
        print("⚠️ Failed to extract SMS fields. One or more regex groups not found.")
        return {
            "ID": "Unknown",
            "Time": "Unknown",
            "From": "Unknown",
            "Size": "Unknown",
            "Content": "Failed to parse SMS content",
        }

    sms_details = {
        "ID": sms_id.group(1),
        "Time": sms_time.group(1),
        "From": sms_from.group(1),
        "Size": sms_size.group(1),
        "Content": sms_content_match.group(1).strip(),
    }

    return sms_details

def create_status_label(status):
    label = QtWidgets.QLabel()
    
    if status == "Online":
        text = '<span style="color: black;">Online </span><span style="color: #34d399; font-size: 20px;">●</span>'
    elif status == "Not Register":
        text = '<span style="color: black;">Not Register </span><span style="color: #708090; font-size: 20px;">●</span>'
    else:
        text = '<span style="color: black;">Offline </span><span style="color: #f87171; font-size: 20px;">●</span>'

    label.setText(text)
    label.setAlignment(Qt.AlignCenter)
    return label

def fetch_all_sms(router_ip):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username, password = get_ssh_credentials()
    ssh.connect(router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
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

def safe_set_text(widget, value):

    text_value = str(value) if value is not None else ""

    if hasattr(widget, "setPlainText"):  
        # QPlainTextEdit
        widget.setPlainText(text_value)
    elif hasattr(widget, "setText"):  
        # QLineEdit, QLabel, QPushButton, dll
        widget.setText(text_value)
    else:
        raise TypeError(f"Widget {type(widget).__name__} is not support with this function")

def safe_get_text(widget):
    if hasattr(widget, "toPlainText"):  # QPlainTextEdit
        return widget.toPlainText().strip()
    elif hasattr(widget, "text"):  # QLineEdit, QLabel, QPushButton, dll
        return widget.text().strip()
    else:
        raise TypeError(f"Widget {type(widget).__name__} tidak mendukung pengambilan teks")

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
    
class SSHCredentialsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path("ssh_credentials_dialog.ui"), self)

        self.config_path = "ssh_key.key"
        self.saveButton.clicked.connect(self.save_credentials)
        self.cancelButton.clicked.connect(self.reject)

        self.load_credentials()

    def load_credentials(self):
        try:
            db_config = get_db_config()
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("SELECT username, password FROM user_ssh ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                self.usernameLineEdit.setText(row[0])
                self.passwordLineEdit.setText(decrypt_password(row[1]))
            cursor.close()
            conn.close()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", str(e))

    def save_credentials(self):
        username = self.usernameLineEdit.text()
        password = self.passwordLineEdit.text()

        if not username or not password:
            QtWidgets.QMessageBox.warning(self, "Missing Fields", "Username and password are required.")
            return

        encrypted = encrypt_password(password)
        try:
            db_config = get_db_config()
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_ssh")  # Replace with UPDATE if per-device later
            cursor.execute("INSERT INTO user_ssh (username, password) VALUES (%s, %s)", (username, encrypted))
            conn.commit()
            cursor.close()
            conn.close()
            QtWidgets.QMessageBox.information(self, "Saved", "SSH credentials updated.")
            self.accept()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))


class DBSettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path("db_settings_dialog.ui"), self)

        self.testButton.clicked.connect(self.test_connection)
        self.saveButton.clicked.connect(self.save_settings)
        self.cancelButton.clicked.connect(self.reject)

        self.config_path = "db_config.json"
        self.load_settings()

    def load_settings(self):
        try:
            with open(self.config_path, "r") as f:
                config = json.load(f)
                self.hostLineEdit.setText(config.get("host", "localhost"))
                self.portSpinBox.setValue(config.get("port", 3306))
                self.userLineEdit.setText(config.get("user", "root"))
                self.passwordLineEdit.setText(config.get("password", ""))
                self.databaseLineEdit.setText(config.get("database", "test"))
                self.databaseTILineEdit.setText(config.get("database_trackit", "test"))
        except FileNotFoundError:
            pass

    def save_settings(self):
        config = {
            "host": self.hostLineEdit.text(),
            "port": self.portSpinBox.value(),
            "user": self.userLineEdit.text(),
            "password": self.passwordLineEdit.text(),
            "database": self.databaseLineEdit.text(),
            "database_trackit": self.databaseTILineEdit.text()
        }
        with open(self.config_path, "w") as f:
            json.dump(config, f, indent=2)
        QtWidgets.QMessageBox.information(self, "Saved", "Database settings saved.")
        self.accept()

    def test_connection(self):
        try:
            conn = mysql.connector.connect(
                host=self.hostLineEdit.text(),
                port=self.portSpinBox.value(),
                user=self.userLineEdit.text(),
                password=self.passwordLineEdit.text(),
                database=self.databaseLineEdit.text()
            )
            conn.close()
            conn = mysql.connector.connect(
                host=self.hostLineEdit.text(),
                port=self.portSpinBox.value(),
                user=self.userLineEdit.text(),
                password=self.passwordLineEdit.text(),
                database=self.databaseTILineEdit.text()
            )
            conn.close()
            QtWidgets.QMessageBox.information(self, "Success", "Connection successful!")
        except mysql.connector.Error as err:
            QtWidgets.QMessageBox.critical(self, "Connection Failed", str(err))

class EmailSettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Email Settings")

        layout = QVBoxLayout()
        form_layout = QtWidgets.QFormLayout()

        self.smtp_server_input = QtWidgets.QLineEdit()
        self.smtp_port_input = QtWidgets.QLineEdit()
        self.email_sender_input = QtWidgets.QLineEdit()
        self.email_password_input = QtWidgets.QLineEdit()
        self.email_password_input.setEchoMode(QtWidgets.QLineEdit.Password)

        form_layout.addRow("SMTP Server:", self.smtp_server_input)
        form_layout.addRow("SMTP Port:", self.smtp_port_input)
        form_layout.addRow("Sender Email:", self.email_sender_input)
        form_layout.addRow("Password:", self.email_password_input)

        layout.addLayout(form_layout)

        save_button = QPushButton("Save")
        save_button.clicked.connect(self.save_settings)
        layout.addWidget(save_button)

        self.setLayout(layout)

        self.load_settings()

    def load_settings(self):
        conn = mysql.connector.connect(**get_db_config())
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT smtp_server, smtp_port, email_sender, email_password FROM email_settings LIMIT 1")
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row:
            self.smtp_server_input.setText(row["smtp_server"])
            self.smtp_port_input.setText(str(row["smtp_port"]))
            self.email_sender_input.setText(row["email_sender"])
            self.email_password_input.setText(row["email_password"])

    def save_settings(self):
        smtp_server = self.smtp_server_input.text()
        smtp_port = self.smtp_port_input.text()
        email_sender = self.email_sender_input.text()
        email_password = self.email_password_input.text()

        conn = mysql.connector.connect(**get_db_config())
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO email_settings (smtp_server, smtp_port, email_sender, email_password)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                smtp_server = VALUES(smtp_server),
                smtp_port = VALUES(smtp_port),
                email_sender = VALUES(email_sender),
                email_password = VALUES(email_password)
        """, (smtp_server, smtp_port, email_sender, email_password))
        conn.commit()
        cursor.close()
        conn.close()

        self.accept()


class WorkerSignals(QObject):
    deviceAdded = pyqtSignal(list)
    smsLogsFetched = pyqtSignal(str, list)
    refreshCompleted = pyqtSignal(list)
    def __init__(self, parent=None):
        super().__init__(parent)

class SMSUpdateSignal(QObject):
    smsFetched = pyqtSignal(int, str)  # row index, SMS text

class IPItem(QtWidgets.QTableWidgetItem):
    """QTableWidgetItem that sorts IPv4 addresses numerically."""
    def __lt__(self, other):
        def ip_key(s):
            try:
                a, b, c, d = (int(x) for x in s.split("."))
                return (a, b, c, d)
            except Exception:
                # Non-IP values go last
                return (999, 999, 999, 999)
        return ip_key(self.text()) < ip_key(other.text())
    
class EmailNotificationDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path("email_notification_list.ui"), self)
        self.saveButton.clicked.connect(self.save_setting)
        self.cancelButton.clicked.connect(self.reject)

        self.loadData()

    def loadData(self):
        try:
            db_config = get_db_config()
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM email_notification LIMIT 1")
            row = cursor.fetchone()
            if row:
                safe_set_text(self.subjectEdit, row[1])
                safe_set_text(self.emailEdit, row[2])
                safe_set_text(self.contentEdit, row[3])
                # self.subjectEdit.setText(row[1])
                # self.emailEdit.setPlainText(row[2])
                # self.contentEdit.setPlainText(row[3])
            cursor.close()
            conn.close()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", str(e))

    def save_setting(self):
        subject = safe_get_text(self.subjectEdit) 
        email = safe_get_text(self.emailEdit) 
        content = safe_get_text(self.contentEdit) 
        # email = self.emailEdit.toPlainText()
        # content = self.contentEdit.toPlainText()

        if not subject or not email or not content:
            QtWidgets.QMessageBox.warning(self, "Missing Fields", "subject, email and content are required.")
            return
        try:
            db_config = get_db_config()
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM email_notification")  # Replace with UPDATE if per-device later
            cursor.execute("INSERT INTO email_notification (subject, email, content) VALUES (%s, %s, %s)", (subject, email, content))
            conn.commit()
            cursor.close()
            conn.close()
            QtWidgets.QMessageBox.information(self, "Saved", "Email Notification Setting updated.")
            self.accept()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

class CiscoSMSMonitorApp(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        
        ui_file = resource_path("combined_sms_monitor.ui")
        uic.loadUi(ui_file, self)
        self.setWindowIcon(QIcon(resource_path("icons/cisco.png")))
        self.statusBar()
        # === Filter & Sort toolbar ===
        toolbar = self.addToolBar("Filter & Sort")
        toolbar.setMovable(False)

        # Status filter
        from PyQt5.QtWidgets import QComboBox, QCheckBox
        toolbar.addWidget(QLabel("Status:"))
        self.statusFilterCombo = QComboBox()
        self.statusFilterCombo.addItems(["All", "Online", "Offline"])
        toolbar.addWidget(self.statusFilterCombo)

        # SIM-only filter
        self.simOnlyCheck = QCheckBox("SIM only")
        toolbar.addWidget(self.simOnlyCheck)

        # Sort controls
        toolbar.addSeparator()
        toolbar.addWidget(QLabel("Sort by:"))
        self.sortByCombo = QComboBox()
        self.sortByCombo.addItems(["Device", "IP", "Status", "Gateway"])
        toolbar.addWidget(self.sortByCombo)

        self.sortOrderButton = QPushButton("Asc")
        self.sortOrderButton.setCheckable(True)  # checked = Desc
        toolbar.addWidget(self.sortOrderButton)

        # Hook up signals
        self.statusFilterCombo.currentIndexChanged.connect(self.apply_filters_and_sort)
        self.simOnlyCheck.toggled.connect(self.apply_filters_and_sort)
        self.sortByCombo.currentIndexChanged.connect(self.apply_filters_and_sort)

        def toggle_sort_order():
            if self.sortOrderButton.isChecked():
                self.sortOrderButton.setText("Desc")
            else:
                self.sortOrderButton.setText("Asc")
            self.apply_filters_and_sort()

        self.sortOrderButton.clicked.connect(toggle_sort_order)

        # Enable interactive sorting by clicking headers too
        self.deviceTable.setSortingEnabled(True)
        self.deviceTable.horizontalHeader().sortIndicatorChanged.connect(
            lambda *_: None  # no-op; sorting is handled automatically by the widget
        )

        menu_bar = self.menuBar()

        settings_menu = menu_bar.addMenu("Settings")

        db_settings_action = QtWidgets.QAction("Database Settings", self)
        db_settings_action.setIcon(QIcon(resource_path("icons/gear.jpg")))  # Optional: add settings icon
        db_settings_action.triggered.connect(self.open_db_settings)

        settings_menu.addAction(db_settings_action)

        email_settings_action = QtWidgets.QAction("Email Settings", self)
        email_settings_action.setIcon(QIcon(resource_path("icons/gear.jpg")))  # Optional: add settings icon
        email_settings_action.triggered.connect(self.open_email_settings_dialog)

        settings_menu.addAction(email_settings_action)

        ssh_settings_action = QtWidgets.QAction(QIcon("icons/ssh.png"),"Manage SSH Credentials", self)
        ssh_settings_action.triggered.connect(self.open_ssh_credentials_dialog)
        settings_menu.addAction(ssh_settings_action)

        notification_list = QtWidgets.QAction(QIcon("icons/gear.jpg"),"Email Notification", self)
        notification_list.triggered.connect(self.open_email_notification)
        settings_menu.addAction(notification_list)

        self.just_added_device = False
        self.worker_signals = WorkerSignals(self)
        self.worker_signals.deviceAdded.connect(self.update_devices_and_ui)
        self.worker_signals.smsLogsFetched.connect(self.display_sms_log_dialog_result)

        self.worker_signals.refreshCompleted.connect(self.update_devices_after_refresh)


        self.sms_signal = SMSUpdateSignal()
        self.sms_signal.smsFetched.connect(self.on_sms_fetched)
        print("Signal connected!")
        self.spinner = LoadingSpinner(self)
        self.spinner.setGeometry(self.rect())  # Match full window

        self.resizeEvent = self._resizeEvent 

        self.devices = load_devices_from_db()
        self.sms_logs = []
        self.is_paused = False

        self.addButton.clicked.connect(self.add_device)
        self.refreshButton.clicked.connect(self.refresh_devices_from_db)
        self.refreshButtonSMS.clicked.connect(self.fetch_all_devices)
        self.searchLineEdit.textChanged.connect(self.filter_devices)
        self.pauseButton.clicked.connect(self.toggle_pause)
        self.exportButton.clicked.connect(self.export_to_csv)
        self.smsSearchLineEdit.textChanged.connect(self.filter_sms_logs)

        self.load_devices(self.devices)

        self.start_syslog_listener()
        # Timer untuk fetch SMS tiap 1 menit
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.fetch_all_devices)  # fungsi yang kamu buat
        self.timer.start(60 * 5000)  # 60 detik

        # Pertama kali langsung jalan
        self.fetch_all_devices()

    def fetch_all_devices(self):
        self.devices = load_devices_from_db()
        print("🔄 Ambil SMS dari semua device...")
        # panggil fungsi fetch_from_all_devices() yang kita buat sebelumnya
        smsList = fetch_from_all_devices(self.devices)
        self.smsTable.setColumnCount(4)
        self.smsTable.setColumnWidth(0, 150)
        self.smsTable.setColumnWidth(1, 150)
        self.smsTable.setColumnWidth(2, 150)
        self.smsTable.setColumnWidth(3, 350)
        self.smsTable.setHorizontalHeaderLabels([
            "Device", "Message Receive", "Message From", "Message Content"
        ])
        self.smsTable.setRowCount(len(smsList))
        for i, d in enumerate(smsList):
            self.smsTable.setItem(i, 0, QtWidgets.QTableWidgetItem(str(d[0] or "")))
            self.smsTable.setItem(i, 1, QtWidgets.QTableWidgetItem(str(d[1] or "")))
            self.smsTable.setItem(i, 2, QtWidgets.QTableWidgetItem(str(d[2] or "")))
            self.smsTable.setItem(i, 3, QtWidgets.QTableWidgetItem(str(d[3] or "")))

    def _resizeEvent(self, event):
        self.spinner.setGeometry(self.rect())  # Keep full size
        super().resizeEvent(event)

    def filter_devices(self):
        self.apply_filters_and_sort()


    def apply_filters_and_sort(self):
        # --- 1) Start from the full device list ---
        devices = list(self.devices)

        # --- 2) Apply text search (same as your filter_devices) ---
        query = (self.searchLineEdit.text() or "").lower().strip()
        if query:
            devices = [
                d for d in devices
                if query in d["name"].lower()
                or query in d["ip"]
                or query in (d.get("sim") or "")
            ]

        # --- 3) Apply Status filter ---
        status_sel = self.statusFilterCombo.currentText()
        if status_sel in ("Online", "Offline"):
            devices = [d for d in devices if d["status"] == status_sel]

        # --- 4) Apply SIM-only filter ---
        if self.simOnlyCheck.isChecked():
            devices = [d for d in devices if (d.get("sim") or "").strip()]

        # --- 5) Sort selection ---
        # Map visible labels to column indices used in the table
        # 0: Device, 1: IP, 2: Gateway, 8: Status (table indices)
        sort_map = {
            "Device": 0,
            "IP": 1,
            "Gateway": 2,
            "Status": 8
        }
        sort_label = self.sortByCombo.currentText()
        sort_col = sort_map.get(sort_label, 0)

        # (Re)load table with filtered devices
        # Preserve current header sort indicator if user clicked the header
        header = self.deviceTable.horizontalHeader()
        cur_sort_col = header.sortIndicatorSection()
        cur_sort_order = header.sortIndicatorOrder()

        self.load_devices(devices)

        # Programmatic sort: prefer toolbar selection; if header already used, keep it.
        if sort_col is not None:
            # Use IP-aware sorting via IPItem (we inserted below in load_devices)
            # Decide order
            order = Qt.AscendingOrder if not self.sortOrderButton.isChecked() else Qt.DescendingOrder
            self.deviceTable.sortItems(sort_col, order)
        else:
            # If unknown selection, keep prior header sorting
            self.deviceTable.sortItems(cur_sort_col, cur_sort_order)


    def get_router_name(self, ip):
        for device in self.devices:
            if device["ip"] == ip:
                return device["name"]
        return ip  # fallback to IP if name not found
    
    def delete_device(self, row_index):
        device = self.devices[row_index]
        name = device.get("name", "Unknown")
        print("Device data at row", row_index, "->", device)
        reply = QtWidgets.QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete device '{name}'?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
        )

        if reply == QtWidgets.QMessageBox.Yes:
            try:
                delete_device_from_db(device["id"])  # Implement this function to delete by ID
                self.devices.pop(row_index)
                self.apply_filters_and_sort()
                QtWidgets.QMessageBox.information(self, "Deleted", f"Device '{name}' was deleted.")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to delete device:\n{e}")

    def open_db_settings(self):
        dialog = DBSettingsDialog(self)
        dialog.exec_()

    def open_email_settings_dialog(self):
        dlg = EmailSettingsDialog(self)
        dlg.exec_()
        
    def open_email_notification(self):
        dlg = EmailNotificationDialog(self)
        dlg.show()

    def open_ssh_credentials_dialog(self):
        dialog = SSHCredentialsDialog(self)
        dialog.exec_()


    def refresh_devices_from_db(self):
        self.spinner.start()

        def refresh_task():
            try:
                devices = load_devices_from_db()
                # Schedule UI update on the main thread
                self.worker_signals.refreshCompleted.emit(devices)
            except Exception as e:
                QTimer.singleShot(0, lambda: QtWidgets.QMessageBox.critical(self, "Error", f"Refresh failed: {e}"))
                QTimer.singleShot(0, self.spinner.stop)

        # ✅ Start the thread (this was missing)
        threading.Thread(target=refresh_task, daemon=True).start()

    @pyqtSlot(list)
    def update_devices_after_refresh(self, devices):
        self.devices = devices
        self.apply_filters_and_sort()
        self.spinner.stop()

    def show_spinner(self):
        self.addButton.setEnabled(False)
        self.spinner_label.setVisible(True)
        self.spinner_movie.start()
        QtWidgets.QApplication.processEvents()

    def hide_spinner(self):
        self.spinner_movie.stop()
        self.spinner_label.setVisible(False)
        self.addButton.setEnabled(True)

    def device_register(self,index):
        ip = self.devices[index]["ip"]
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        username, password = get_ssh_credentials()
        ssh.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        shell = ssh.invoke_shell()
        commands = [
            "conf t",
            f"logging host {get_ip_address()}",
            "end",
            "write memory"
        ]

        for cmd in commands:
            shell.send(cmd + "\n")
            import time
            time.sleep(1)  # kasih jeda supaya Cisco proses command
        time.sleep(2)  # tunggu output terkumpul
        output = shell.recv(5000).decode()
        ssh.close()
        devices = load_devices_from_db()
        self.load_devices(devices)

    
    def load_devices(self, device_list):
        print(f"🔄 Loading {len(device_list)} devices into table")
        self.deviceTable.setSortingEnabled(False)  # prevent churn while filling

        self.deviceTable.setColumnCount(10)
        self.deviceTable.setHorizontalHeaderLabels([
            "Device", "IP", "Gateway", "SIM", "APN", "Email", "Last SMS", "Signal", "Status", "Actions"
        ])
        self.deviceTable.setRowCount(len(device_list))

        for i, d in enumerate(device_list):
            # Device
            self.deviceTable.setItem(i, 0, QtWidgets.QTableWidgetItem(d["name"]))

            # IP (use IPItem for correct numeric sorting)
            self.deviceTable.setItem(i, 1, IPItem(d["ip"]))

            # Gateway
            self.deviceTable.setItem(i, 2, QtWidgets.QTableWidgetItem(d["gateway"]))

            # SIM / APN / Email
            self.deviceTable.setItem(i, 3, QtWidgets.QTableWidgetItem(d["sim"]))
            self.deviceTable.setItem(i, 4, QtWidgets.QTableWidgetItem(d["apn"]))
            self.deviceTable.setItem(i, 5, QtWidgets.QTableWidgetItem(d["email"]))

            # Last SMS placeholder
            self.deviceTable.setItem(i, 6, QtWidgets.QTableWidgetItem("Loading..."))

            # Signal bars
            self.deviceTable.setItem(i, 7, QtWidgets.QTableWidgetItem("▓" * d.get("signal", 0)))

            # Status (string sort is fine, “Offline” > “Online”; toolbar lets user flip order)
            status_widget = create_status_label(device_list[i]["status"])
            self.deviceTable.setCellWidget(i, 8, status_widget)

           
            # Create dropdown menu
            if device_list[i]["status"] == "Not Register":
                action_button = QToolButton()
                action_button.setText("Device Register")
                action_button.setIcon(QIcon(resource_path("icons/gear.jpg")))
                action_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
                action_button.clicked.connect(lambda _, row=i: self.device_register(row))
            else:
                action_button = QToolButton()
                action_button.setText("Edit")
                action_button.setIcon(QIcon(resource_path("icons/edit.png")))
                action_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
                action_button.setPopupMode(QToolButton.MenuButtonPopup)
            # Actions (menu) — unchanged except the bit we added earlier for SIM check
            action_button = QToolButton()
            action_button.setText("Edit")
            action_button.setIcon(QIcon(resource_path("icons/edit.png")))
            action_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            action_button.setPopupMode(QToolButton.MenuButtonPopup)

            menu = QMenu(action_button)
            sms_logs_action = QAction(QIcon(resource_path("icons/sms.png")),"SMS Logs", self)
            send_sms_action = QAction(QIcon(resource_path("icons/send.png")),"Send SMS", self)
            delete_action = QAction(QIcon(resource_path("icons/delete.png")),"Delete", self)

            menu.addAction(sms_logs_action)

            sim_present = bool((d.get("sim") or "").strip())
            send_sms_action.setEnabled(sim_present)
            if not sim_present:
                # status tip shows in your status bar (we enabled it)
                send_sms_action.setStatusTip("Send SMS disabled: SIM is empty for this device")
                # optional: put a disabled reason line above it (uncomment if you like)
                # reason_action = QAction("⚠️ SIM required to send SMS", self)
                # reason_action.setEnabled(False)
                # menu.addAction(reason_action)

            menu.addAction(send_sms_action)
            menu.addSeparator()
            menu.addAction(delete_action)



            action_button.setMenu(menu)

            action_button.clicked.connect(lambda _, row=i: self.open_settings_dialog(row))
            sms_logs_action.triggered.connect(lambda _, row=i: self.show_sms_log_dialog(row))
            send_sms_action.triggered.connect(lambda _, row=i: self.show_send_sms_dialog(row))
            delete_action.triggered.connect(lambda _, row=i: self.delete_device(row))

            self.deviceTable.setCellWidget(i, 9, action_button)

        # Kick off async “Last SMS” fetches
        for i, d in enumerate(device_list):
            QTimer.singleShot(100 + i * 100, lambda row=i, ip=d["ip"]: self.update_last_sms(row, ip))

        self.deviceTable.setSortingEnabled(True)  # re-enable interactive sorting

    def update_last_sms(self, row, ip):
        def run():
            sms = fetch_last_sms(ip)
            self.sms_signal.smsFetched.emit(row, sms)

        threading.Thread(target=run, daemon=True).start()

    @pyqtSlot(int, str)
    def on_sms_fetched(self, row, sms):
        self.deviceTable.setItem(row, 6, QtWidgets.QTableWidgetItem(sms))


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
            self.apply_filters_and_sort()
            QtWidgets.QMessageBox.information(self, "Success", "Device updated successfully.")


    def add_device(self):
        dialog = DeviceSettingsDialog(parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            new_device = dialog.get_data()
            self.spinner.start()
            self.just_added_device = True  # <-- set flag

            def background_task():
                try:
                    insert_device_to_db(new_device)
                    username, password = get_ssh_credentials()
                    configure_sms_applet_on_cisco(
                        router_ip=new_device["ip"],
                        username=username,
                        password=password
                    )
                    time.sleep(2)
                    updated_devices = load_devices_from_db()

                    # Emit signal on main thread
                    self.worker_signals.deviceAdded.emit(updated_devices)
                except Exception as e:
                    QTimer.singleShot(0, lambda: QtWidgets.QMessageBox.warning(
                        self, "Error", f"Failed to add device:\n{e}"
                    ))

            threading.Thread(target=background_task, daemon=True).start()

    @pyqtSlot(list)
    def update_devices_and_ui(self, updated_devices):
        self.spinner.stop()
        self.devices = updated_devices
        self.apply_filters_and_sort()

    def show_sms_log_dialog(self, index):
        self.spinner.start()
        name = self.devices[index]["name"]
        ip = self.devices[index]["ip"]

        def task():
            try:
                logs = fetch_all_sms(ip)
                self.worker_signals.smsLogsFetched.emit(name, logs)
            except Exception as e:
                QTimer.singleShot(0, lambda: QtWidgets.QMessageBox.critical(self, "Error", str(e)))
                self.worker_signals.smsLogsFetched.emit(name, [])

        threading.Thread(target=task, daemon=True).start()

    @pyqtSlot(str, list)
    def display_sms_log_dialog_result(self, name, logs):
        self.spinner.stop()
        dialog = SMSLogDialog(device_name=name, sms_logs=logs, parent=self)
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
            formatted_time = sms["Time"]
            try:
                dt_obj = datetime.strptime(sms["Time"], "%y-%m-%d %H:%M:%S")  # e.g. "25-05-28 14:38:06"
                formatted_time = dt_obj.strftime("%d/%m/%Y %H:%M:%S")
            except Exception as e:
                print(f"⚠️ Time format error: {e} -> using raw")

            self.smsTable.setItem(i, 0, QtWidgets.QTableWidgetItem(sms.get("Router", "Unknown")))
            self.smsTable.setItem(i, 1, QtWidgets.QTableWidgetItem(sms["ID"]))
            self.smsTable.setItem(i, 2, QtWidgets.QTableWidgetItem(formatted_time))
            self.smsTable.setItem(i, 3, QtWidgets.QTableWidgetItem(sms["From"]))
            self.smsTable.setItem(i, 4, QtWidgets.QTableWidgetItem(str(sms["Size"])))
            self.smsTable.setItem(i, 5, QtWidgets.QTableWidgetItem(sms["Content"]))

    def send_sms(self, router_ip, username, password, recipient, message):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)

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

        # ✅ Guard: block if SIM is empty
        if not (device.get("sim") or "").strip():
            QtWidgets.QMessageBox.warning(
                self,
                "SIM Missing",
                f"Cannot send SMS for '{device.get('name','Unknown')}'.\nPlease set the SIM value first."
            )
            return

        dialog = SendSMSDialog(device_name=device["name"], router_ip=device["ip"], parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            to_number, message = dialog.get_sms_data()
            username, password = get_ssh_credentials()
            self.send_sms(device["ip"], username, password, to_number, message)

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
                    last_two_digits = "".join(router_ip.split(".")[-2:])
                    router_ip = f"192.168.{last_two_digits}"
                    send_email(sms, get_email_by_router_ip(router_ip))
                    sms["Router"] = self.get_router_name(router_ip)
                    self.add_sms_log(sms)
                else:
                    print("⚠️ Pattern not matched.")
        t = threading.Thread(target=listen, daemon=True)
        t.start()

def main():
    try:
        app = QtWidgets.QApplication(sys.argv)
        app_icon = QIcon(resource_path("cisco.ico"))
        app.setWindowIcon(app_icon)
        window = CiscoSMSMonitorApp()
        window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"❌ App crashed: {e}")
        traceback.print_exc()
if __name__ == "__main__":
    main()
