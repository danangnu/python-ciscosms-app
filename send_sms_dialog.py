# send_sms_dialog.py

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QVBoxLayout, QPushButton

from iccid_dialogs import ICCIDPickerDialog   # assumes you already moved this


class SendSMSDialog(QtWidgets.QDialog):
    def __init__(self, device_name: str, router_ip: str, parent=None):
        super().__init__(parent)

        self.setWindowTitle(f"Send SMS via {device_name}")
        self.setFixedSize(360, 220)

        layout = QVBoxLayout()

        # --- "To" row: line edit + ICCID search button -----------------
        layout.addWidget(QtWidgets.QLabel("To:"))

        to_row = QtWidgets.QHBoxLayout()
        self.to_input = QtWidgets.QLineEdit()
        self.to_input.setPlaceholderText("Recipient Number")

        self.iccid_btn = QPushButton("Search By ICCID")

        to_row.addWidget(self.to_input)
        to_row.addWidget(self.iccid_btn)
        layout.addLayout(to_row)

        # --- Message ---------------------------------------------------
        layout.addWidget(QtWidgets.QLabel("Message:"))
        self.message_input = QtWidgets.QPlainTextEdit()
        self.message_input.setPlaceholderText("Enter your message")
        layout.addWidget(self.message_input)

        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.accept)
        layout.addWidget(send_btn)

        self.setLayout(layout)
        self.router_ip = router_ip

        # Wire ICCID button
        self.iccid_btn.clicked.connect(self._on_search_iccid)

    def _on_search_iccid(self):
        dlg = ICCIDPickerDialog(self)
        if dlg.exec_() == QtWidgets.QDialog.Accepted and dlg.selected_phone:
            # Put selected phone number into "To" field
            self.to_input.setText(dlg.selected_phone)

    def get_sms_data(self):
        return self.to_input.text(), self.message_input.toPlainText()