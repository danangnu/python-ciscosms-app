from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QDateTimeEdit, QPushButton, QLabel, QHBoxLayout
from PyQt5.QtCore import QDateTime
from datetime import datetime

class SMSLogDialog(QtWidgets.QDialog):
    def __init__(self, device_name, sms_logs, parent=None):
        super(SMSLogDialog, self).__init__(parent)
        self.setWindowTitle("📋 SMS Logs")
        self.resize(800, 400)

        self.sms_logs = sms_logs
        self.device_name = device_name

        self.init_ui()

    def init_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # Header label
        title_label = QtWidgets.QLabel(f"SMS Logs for {self.device_name}")
        title_label.setStyleSheet("font-weight: bold; margin-bottom: 10px;")
        layout.addWidget(title_label)

        # Date filter controls
        self.startDateEdit = QDateTimeEdit(self)
        self.startDateEdit.setDisplayFormat("dd/MM/yyyy HH:mm:ss")
        self.startDateEdit.setDateTime(QDateTime.currentDateTime().addDays(-7))

        self.endDateEdit = QDateTimeEdit(self)
        self.endDateEdit.setDisplayFormat("dd/MM/yyyy HH:mm:ss")
        self.endDateEdit.setDateTime(QDateTime.currentDateTime())

        self.filterButton = QPushButton("Filter")
        self.filterButton.clicked.connect(self.apply_date_filter)

        self.resetButton = QPushButton("Reset")
        self.resetButton.clicked.connect(self.reset_filter)

        filterLayout = QHBoxLayout()
        filterLayout.addWidget(QLabel("From:"))
        filterLayout.addWidget(self.startDateEdit)
        filterLayout.addWidget(QLabel("To:"))
        filterLayout.addWidget(self.endDateEdit)
        filterLayout.addWidget(self.filterButton)
        filterLayout.addWidget(self.resetButton)
        layout.addLayout(filterLayout)

        # SMS table
        self.table = QtWidgets.QTableWidget(self)
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["ID", "Time", "From", "Size", "Content"])
        layout.addWidget(self.table)

        # Close button
        close_button = QtWidgets.QPushButton("Close")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)

        # Load initial data
        self.display_sms_logs(self.sms_logs)

    def display_sms_logs(self, logs):
        self.table.setRowCount(len(logs))
        for i, sms in enumerate(logs):
            self.table.setItem(i, 0, QtWidgets.QTableWidgetItem(str(sms["ID"])))

            try:
                # Convert from 'yy-MM-dd HH:mm:ss' to 'dd/MM/yyyy HH:mm:ss'
                dt = datetime.strptime(sms["Time"], "%y-%m-%d %H:%M:%S")
                formatted_time = dt.strftime("%d/%m/%Y %H:%M:%S")
            except Exception as e:
                formatted_time = sms["Time"]  # fallback
                print(f"⚠️ Failed to format time: {sms['Time']} -> {e}")

            self.table.setItem(i, 1, QtWidgets.QTableWidgetItem(formatted_time))
            self.table.setItem(i, 2, QtWidgets.QTableWidgetItem(sms["From"]))
            self.table.setItem(i, 3, QtWidgets.QTableWidgetItem(str(sms["Size"])))
            self.table.setItem(i, 4, QtWidgets.QTableWidgetItem(sms["Content"]))

        self.table.resizeColumnsToContents()

    def apply_date_filter(self):
        start = self.startDateEdit.dateTime().toPyDateTime()
        end = self.endDateEdit.dateTime().toPyDateTime()

        filtered_logs = []
        for sms in self.sms_logs:
            try:
                sms_time = datetime.strptime(sms["Time"], "%y-%m-%d %H:%M:%S")
                if start <= sms_time <= end:
                    filtered_logs.append(sms)
            except Exception as e:
                print(f"❌ Error parsing time: {sms['Time']} -> {e}")

        self.display_sms_logs(filtered_logs)

    def reset_filter(self):
        self.startDateEdit.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.endDateEdit.setDateTime(QDateTime.currentDateTime())
        self.display_sms_logs(self.sms_logs)

