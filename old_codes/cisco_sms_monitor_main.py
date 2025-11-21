
from PyQt5 import QtWidgets, uic
import sys
from sms_log_dialog import SMSLogDialog

class DeviceSettingsDialog(QtWidgets.QDialog):
    def __init__(self, device=None, parent=None):
        super(DeviceSettingsDialog, self).__init__(parent)
        uic.loadUi("device_settings_dialog.ui", self)
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

class CiscoSMSMonitor(QtWidgets.QMainWindow):
    def __init__(self):
        super(CiscoSMSMonitor, self).__init__()
        uic.loadUi("cisco_sms_monitor.ui", self)
        self.devices = [
            {"name": "Router A", "ip": "192.168.1.1", "sim": "628123456789", "apn": "internet.telkomsel", "email": "alerts@domain.com", "lastSMS": "Test OK", "signal": 4},
            {"name": "Router B", "ip": "192.168.1.2", "sim": "628223456789", "apn": "3data", "email": "support@x.com", "lastSMS": "Low signal", "signal": 2}
        ]
        self.display_devices(self.devices)
        self.addButton.clicked.connect(self.add_device)
        self.refreshButton.clicked.connect(lambda: self.display_devices(self.devices))
        self.searchLineEdit.textChanged.connect(self.filter_devices)

    def display_devices(self, device_list):
        self.deviceTable.setRowCount(len(device_list))
        self.deviceTable.setColumnCount(8)
        self.deviceTable.setHorizontalHeaderLabels(["Device", "IP", "SIM", "APN", "Email", "Last SMS", "Signal", "Actions"])

        for i, device in enumerate(device_list):
            self.deviceTable.setItem(i, 0, QtWidgets.QTableWidgetItem(device["name"]))
            self.deviceTable.setItem(i, 1, QtWidgets.QTableWidgetItem(device["ip"]))
            self.deviceTable.setItem(i, 2, QtWidgets.QTableWidgetItem(device["sim"]))
            self.deviceTable.setItem(i, 3, QtWidgets.QTableWidgetItem(device["apn"]))
            self.deviceTable.setItem(i, 4, QtWidgets.QTableWidgetItem(device["email"]))
            self.deviceTable.setItem(i, 5, QtWidgets.QTableWidgetItem(device["lastSMS"]))
            self.deviceTable.setItem(i, 6, QtWidgets.QTableWidgetItem("▓" * device["signal"]))

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
            self.display_devices(self.devices)

    def add_device(self):
        dialog = DeviceSettingsDialog(parent=self)
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            new_device = dialog.get_data()
            new_device["lastSMS"] = ""
            new_device["signal"] = 3
            self.devices.append(new_device)
            self.display_devices(self.devices)

    def show_sms_log_dialog(self, index):
        logs = [
            {"id": 2, "time": "25-04-30 11:50:09", "from": "6281335588004", "size": 8, "message": "Yes send"},
            {"id": 3, "time": "25-04-30 12:00:00", "from": "6281112345678", "size": 12, "message": "Hello again!"}
        ]
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
        self.display_devices(filtered)

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = CiscoSMSMonitor()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
