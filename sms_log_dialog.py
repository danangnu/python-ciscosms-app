
from PyQt5 import QtWidgets, uic

class SMSLogDialog(QtWidgets.QDialog):
    def __init__(self, device_name="", sms_logs=None, parent=None):
        super(SMSLogDialog, self).__init__(parent)
        uic.loadUi("sms_log_dialog.ui", self)
        self.deviceLabel.setText(f"SMS Logs for {device_name}")
        self.closeButton.clicked.connect(self.close)

        self.smsTable.setColumnCount(5)
        self.smsTable.setHorizontalHeaderLabels(["ID", "Time", "From", "Size", "Message"])
        self.smsTable.setRowCount(len(sms_logs or []))

        for i, sms in enumerate(sms_logs or []):
            self.smsTable.setItem(i, 0, QtWidgets.QTableWidgetItem(str(sms["id"])))
            self.smsTable.setItem(i, 1, QtWidgets.QTableWidgetItem(sms["time"]))
            self.smsTable.setItem(i, 2, QtWidgets.QTableWidgetItem(sms["from"]))
            self.smsTable.setItem(i, 3, QtWidgets.QTableWidgetItem(str(sms["size"])))
            self.smsTable.setItem(i, 4, QtWidgets.QTableWidgetItem(sms["message"]))
