# iccid_dialogs.py
from PyQt5 import QtWidgets


class ICCIDEditDialog(QtWidgets.QDialog):
    """
    Simple dialog to add / edit one ICCID mapping.
    Returns (iccid, phone, description) via get_data().
    """
    def __init__(self, parent=None, iccid="", phone="", description=""):
        super().__init__(parent)
        self.setWindowTitle("Edit ICCID Mapping")
        self.resize(420, 180)

        self._iccid_edit = QtWidgets.QLineEdit(iccid, self)
        self._phone_edit = QtWidgets.QLineEdit(phone, self)
        self._desc_edit = QtWidgets.QLineEdit(description, self)

        form = QtWidgets.QFormLayout()
        form.addRow("ICCID:", self._iccid_edit)
        form.addRow("Phone:", self._phone_edit)
        form.addRow("Description:", self._desc_edit)

        btn_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel,
            parent=self,
        )
        btn_box.accepted.connect(self._on_ok)
        btn_box.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(btn_box)

    def _on_ok(self):
        iccid = self._iccid_edit.text().strip()
        phone = self._phone_edit.text().strip()
        if not iccid or not phone:
            QtWidgets.QMessageBox.warning(
                self, "Missing data", "ICCID and phone number are required."
            )
            return
        self.accept()

    def get_data(self):
        return (
            self._iccid_edit.text().strip(),
            self._phone_edit.text().strip(),
            self._desc_edit.text().strip(),
        )


class ICCIDPickerDialog(QtWidgets.QDialog):
    """
    Generic ICCID picker dialog.

    It does NOT talk to the DB directly; instead you inject:
      fetch_rows(term) -> list[(iccid, phone, desc)]
      insert_row(iccid, phone, desc) -> (ok: bool, err: str | None)
    """

    def __init__(self, parent=None, fetch_rows=None, insert_row=None):
        super().__init__(parent)
        self.setWindowTitle("Select SIM by ICCID")
        self.resize(600, 420)

        self._fetch_rows = fetch_rows
        self._insert_row = insert_row

        self.selected_iccid = None
        self.selected_phone = None

        layout = QtWidgets.QVBoxLayout(self)

        # --- Search box -------------------------------------------------
        search_layout = QtWidgets.QHBoxLayout()
        self.search_edit = QtWidgets.QLineEdit(self)
        self.search_edit.setPlaceholderText(
            "Search by ICCID / phone / description..."
        )
        search_layout.addWidget(QtWidgets.QLabel("Search:", self))
        search_layout.addWidget(self.search_edit)
        layout.addLayout(search_layout)

        # --- Table ------------------------------------------------------
        self.table = QtWidgets.QTableWidget(self)
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["ICCID", "Phone", "Description"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table)

        # --- Bottom row: Add… + OK/Cancel -------------------------------
        bottom_layout = QtWidgets.QHBoxLayout()

        self.add_btn = QtWidgets.QPushButton("Add…", self)
        bottom_layout.addWidget(self.add_btn)
        bottom_layout.addStretch(1)

        btn_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel,
            parent=self,
        )
        bottom_layout.addWidget(btn_box)

        layout.addLayout(bottom_layout)

        # Signals
        self.search_edit.textChanged.connect(self._reload_rows)
        self.table.itemDoubleClicked.connect(self._accept_current_row)
        btn_box.accepted.connect(self._on_ok)
        btn_box.rejected.connect(self.reject)
        self.add_btn.clicked.connect(self._on_add_clicked)

        # initial load
        self._reload_rows()

    # ---------- data loading -------------------------------------------
    def _reload_rows(self):
        if not self._fetch_rows:
            self.table.setRowCount(0)
            return

        rows = self._fetch_rows(self.search_edit.text())
        self.table.setRowCount(len(rows))
        for r, (iccid, phone, desc) in enumerate(rows):
            self.table.setItem(r, 0, QtWidgets.QTableWidgetItem(iccid or ""))
            self.table.setItem(r, 1, QtWidgets.QTableWidgetItem(phone or ""))
            self.table.setItem(r, 2, QtWidgets.QTableWidgetItem(desc or ""))

    # ---------- selection helpers --------------------------------------
    def _set_from_row(self, row: int):
        if row < 0:
            return
        iccid_item = self.table.item(row, 0)
        phone_item = self.table.item(row, 1)
        if not iccid_item or not phone_item:
            return
        self.selected_iccid = iccid_item.text().strip()
        self.selected_phone = phone_item.text().strip()

    def _accept_current_row(self, *_):
        row = self.table.currentRow()
        self._set_from_row(row)
        if self.selected_phone:
            self.accept()

    def _on_ok(self):
        row = self.table.currentRow()
        self._set_from_row(row)
        if not self.selected_phone:
            QtWidgets.QMessageBox.warning(
                self, "No selection", "Please select a SIM row to use."
            )
            return
        self.accept()

    # ---------- add new ICCID ------------------------------------------
    def _on_add_clicked(self):
        if not self._insert_row:
            QtWidgets.QMessageBox.warning(
                self,
                "Unavailable",
                "Insert function is not wired; cannot add ICCID here.",
            )
            return

        dlg = ICCIDEditDialog(self)
        if dlg.exec_() != QtWidgets.QDialog.Accepted:
            return

        iccid, phone, desc = dlg.get_data()
        ok, err = self._insert_row(iccid, phone, desc or None)
        if not ok:
            QtWidgets.QMessageBox.critical(
                self,
                "Insert failed",
                f"Could not save ICCID mapping:\n{err}",
            )
            return

        # Refresh and focus on the new ICCID
        self.search_edit.setText(iccid)
        self._reload_rows()