from PyQt5 import QtCore, QtGui, QtWidgets

DEVICE_HUB_ROLE = QtCore.Qt.UserRole + 101  # custom role to store is_hub flag

class DeviceDelegate(QtWidgets.QStyledItemDelegate):
    def paint(self, painter: QtGui.QPainter, option: QtWidgets.QStyleOptionViewItem, index: QtCore.QModelIndex):
        opt = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)

        # draw selection/row background as usual
        style = opt.widget.style() if opt.widget else QtWidgets.QApplication.style()
        style.drawPrimitive(QtWidgets.QStyle.PE_PanelItemViewItem, opt, painter, opt.widget)

        # we will draw text ourselves
        text = index.data(QtCore.Qt.DisplayRole) or ""
        is_hub = bool(index.data(DEVICE_HUB_ROLE))

        r = opt.rect.adjusted(8, 0, -8, 0)  # left/right padding
        painter.save()
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        painter.setPen(QtCore.Qt.NoPen)
        painter.setFont(opt.font)  # EXACT same font the view uses

        x = r.left()
        y = r.top()
        h = r.height()

        # optional: HUB pill
        if is_hub:
            pill_margin_h = 6
            pill_margin_v = 4
            pill_text = "HUB"
            # size using the SAME font metrics the table uses
            fm = QtGui.QFontMetrics(opt.font)
            tw = fm.horizontalAdvance(pill_text)
            ph = fm.height() + pill_margin_v   # pill height ~ text height
            pw = tw + 16                       # padding inside the pill
            pill_rect = QtCore.QRect(x, y + (h - ph)//2, pw, ph)

            # pill background
            painter.setBrush(QtGui.QColor("#2563eb"))
            painter.drawRoundedRect(pill_rect, 6, 6)

            # pill text
            painter.setPen(QtCore.Qt.white)
            painter.drawText(pill_rect.adjusted(8, 0, -8, 0),
                             QtCore.Qt.AlignVCenter | QtCore.Qt.AlignHCenter,
                             pill_text)

            x = pill_rect.right() + 8  # space between pill and device name

        # device name (same font/color/path as other items)
        name_rect = QtCore.QRect(x, r.top(), r.right() - x, r.height())
        # use view palette for text color so selection states match
        painter.setPen(opt.palette.color(
            QtGui.QPalette.HighlightedText if (opt.state & QtWidgets.QStyle.State_Selected)
            else QtGui.QPalette.Text
        ))
        painter.drawText(name_rect, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft,
                         text)

        painter.restore()

    def sizeHint(self, option, index):
        # keep default row height logic
        return super().sizeHint(option, index)