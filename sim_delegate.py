# sim_delegate.py
from PyQt5 import QtCore, QtGui, QtWidgets
from pill_utils import paint_pill   # <— NEW

DEVICE_ID_ROLE = QtCore.Qt.UserRole + 200
SIM_TEXT_ROLE  = QtCore.Qt.UserRole + 201


class SimDelegate(QtWidgets.QStyledItemDelegate):
    """
    SIM column:
      - 'NO CELL' pill when empty
      - SIM text + send icon when present
      - emits sendSmsRequested(device_id, sim_number) when icon clicked
    """
    sendSmsRequested = QtCore.pyqtSignal(int, str)

    def __init__(self, parent=None, icon: QtGui.QIcon | None = None):
        super().__init__(parent)
        self.icon = icon or QtGui.QIcon()
        self._paint_pill = paint_pill
        self._last_icon_rect: dict[QtCore.QModelIndex, QtCore.QRect] = {}

    def paint(self, painter, option, index):
        opt = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)

        style = opt.widget.style() if opt.widget else QtWidgets.QApplication.style()
        style.drawPrimitive(QtWidgets.QStyle.PE_PanelItemViewItem, opt, painter, opt.widget)

        painter.save()
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        painter.setFont(opt.font)

        text = (index.data(SIM_TEXT_ROLE) or "").strip()
        r = opt.rect.adjusted(8, 0, -8, 0)

        if not text:
            # draw NO CELL pill
            self._paint_pill(painter, r, "NO CELL", opt.font)
            self._last_icon_rect[index] = QtCore.QRect()
            painter.restore()
            return

        # SIM text + icon
        fm = QtGui.QFontMetrics(opt.font)
        icon_sz = min(max(fm.height(), 16), 20)
        icon_rect = QtCore.QRect(
            r.right() - icon_sz,
            r.top() + (r.height() - icon_sz) // 2,
            icon_sz,
            icon_sz,
        )
        text_rect = QtCore.QRect(
            r.left(), r.top(),
            icon_rect.left() - 8 - r.left(),
            r.height()
        )

        painter.setPen(opt.palette.color(
            QtGui.QPalette.HighlightedText
            if (opt.state & QtWidgets.QStyle.State_Selected)
            else QtGui.QPalette.Text
        ))
        painter.drawText(text_rect, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, text)

        if not self.icon.isNull():
            pm = self.icon.pixmap(icon_sz, icon_sz)
            style.drawItemPixmap(painter, icon_rect, QtCore.Qt.AlignCenter, pm)

        self._last_icon_rect[index] = icon_rect
        painter.restore()

    def editorEvent(self, event, model, option, index):
        if (event.type() == QtCore.QEvent.MouseButtonRelease and
                event.button() == QtCore.Qt.LeftButton):
            icon_rect = self._last_icon_rect.get(index, QtCore.QRect())
            if icon_rect.contains(event.pos()):
                dev_id = int(index.data(DEVICE_ID_ROLE) or 0)
                sim_to = (index.data(SIM_TEXT_ROLE) or "").strip()
                if dev_id and sim_to:
                    self.sendSmsRequested.emit(dev_id, sim_to)
                return True
        return super().editorEvent(event, model, option, index)