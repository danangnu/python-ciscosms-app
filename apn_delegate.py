# apn_delegate.py
from PyQt5 import QtCore, QtGui, QtWidgets
from pill_utils import paint_pill

APN_TEXT_ROLE = QtCore.Qt.UserRole + 202


class ApnDelegate(QtWidgets.QStyledItemDelegate):
    def paint(self, painter, option, index):
        opt = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        style = opt.widget.style() if opt.widget else QtWidgets.QApplication.style()
        style.drawPrimitive(QtWidgets.QStyle.PE_PanelItemViewItem, opt, painter, opt.widget)

        painter.save()
        painter.setFont(opt.font)

        text = (index.data(APN_TEXT_ROLE) or "").strip()
        r = opt.rect.adjusted(8, 0, -8, 0)

        if not text:
            paint_pill(painter, r, "NO CELL", opt.font)
        else:
            color = opt.palette.color(
                QtGui.QPalette.HighlightedText
                if (opt.state & QtWidgets.QStyle.State_Selected)
                else QtGui.QPalette.Text
            )
            painter.setPen(color)
            painter.drawText(r, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, text)

        painter.restore()