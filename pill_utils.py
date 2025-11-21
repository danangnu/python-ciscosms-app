# pill_utils.py
from PyQt5 import QtCore, QtGui, QtWidgets

def paint_pill(painter: QtGui.QPainter, rect: QtCore.QRect, text: str, font: QtGui.QFont):
    """
    Draws a rounded "pill" badge, used for NO CELL in SIM/APN columns.
    This version uses a darker background + text.
    """
    if not text:
        return

    painter.save()
    painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
    painter.setFont(font)

    # Slight inset so the pill doesn't touch cell borders
    r = rect.adjusted(2, 4, -2, -4)

    # Darker colors than before
    bg_color     = QtGui.QColor("#D0D3DC")   # pill background
    border_color = QtGui.QColor("#B0B4BF")   # pill border
    text_color   = QtGui.QColor("#40444F")   # pill text

    # Background
    painter.setPen(QtCore.Qt.NoPen)
    painter.setBrush(bg_color)
    radius = r.height() / 2.0
    painter.drawRoundedRect(r, radius, radius)

    # Border (optional – comment out if you don't want it)
    painter.setPen(border_color)
    painter.setBrush(QtCore.Qt.NoBrush)
    painter.drawRoundedRect(r, radius, radius)

    # Text
    painter.setPen(text_color)
    painter.drawText(
        r.adjusted(8, 0, -8, 0),
        QtCore.Qt.AlignCenter,
        text,
    )

    painter.restore()