# -*- coding: utf-8 -*-
import os
import sys
import socket
import paramiko
import time
import threading
import re
import json
import smtplib
import ipaddress
from cryptography.fernet import Fernet
from datetime import datetime
from PyQt5 import QtWidgets, uic, QtCore
from sms_log_dialog import SMSLogDialog
from PyQt5.QtGui import QMovie, QIcon
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QSize, QTimer, QObject, pyqtSignal, pyqtSlot
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QHBoxLayout, QLabel,
    QToolButton, QMenu, QAction, QTabWidget, QComboBox, QTableWidget,
    QTableWidgetItem
)
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import mysql.connector
import traceback
from concurrent.futures import ThreadPoolExecutor
from paramiko.ssh_exception import SSHException

from collections import deque
_RECENT_SENDERS = deque(maxlen=200)
_RECENT_LOCK = threading.Lock()
RECENT_SENDER_WINDOW_SEC = 3 * 60  # 3 minutes is plenty
RECENT_SENDER_WINDOW_SEC = 900  # 15 min
_clock = time.time

# put near imports once
_PROMPT_LINE_RE = re.compile(rb'^[^\r\n]*[>#]\s*$', re.M)
_TERM_LEN_RE    = re.compile(r'(?:\bterminal\b.*\blength\b|^term\s+len.*$|length\s*=\s*0)', re.I)

# ---------- Helpers / resources ----------
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def _strip_term_len_noise(s: str) -> str:
    if not s: return s
    return '\n'.join(ln for ln in s.splitlines() if not _TERM_LEN_RE.search(ln))

def _capture_prompt(chan, timeout: float = 3.0) -> bytes:
    """Return the current prompt line (bytes, no CRLF)."""
    deadline = time.time() + timeout
    buf = bytearray()
    # ask device to print a prompt
    chan.send('\n')
    while time.time() < deadline:
        if chan.recv_ready():
            chunk = chan.recv(65535)
            if not chunk:
                break
            buf.extend(chunk)
            # scan last few lines for a prompt-like line
            tail = bytes(buf[-2048:])
            m = _PROMPT_LINE_RE.search(tail)
            if m:
                # return the last matching line
                lines = tail.splitlines()
                for i in range(len(lines) - 1, -1, -1):
                    if _PROMPT_LINE_RE.match(lines[i]):
                        return lines[i].rstrip()
        else:
            time.sleep(0.03)
    # fallback: generic
    return b'#'

# --- Unified pill painter (matches APN visual) ---
def paint_pill(painter: QtGui.QPainter, rect: QtCore.QRect, text: str, base_font: QtGui.QFont):
    f = QtGui.QFont(base_font)
    f.setBold(True)                                # APN badge is bold
    painter.setFont(f)
    fm = QtGui.QFontMetrics(f)

    pad_h, pad_v, radius = 6, 2, 6                 # APN padding & radius
    tw = fm.horizontalAdvance(text)
    ph = fm.height() + 2 * pad_v
    pw = tw + 2 * pad_h

    pill = QtCore.QRect(
        rect.left(),
        rect.top() + (rect.height() - ph) // 2,
        pw, ph
    )

    painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
    painter.setPen(QtCore.Qt.NoPen)
    painter.setBrush(QtGui.QColor("#6b7280"))      # APN gray
    painter.drawRoundedRect(pill, radius, radius)

    painter.setPen(QtCore.Qt.white)
    painter.drawText(pill.adjusted(pad_h, 0, -pad_h, 0),
                    QtCore.Qt.AlignCenter, text)
    return pill
    
# --- UI helper: SIM cell (number + send button) ---
def make_sim_cell(sim_text: str, dev_id: int, on_send_cb) -> QWidget:
    w = QWidget()
    l = QHBoxLayout(w)
    l.setContentsMargins(6, 0, 6, 0)
    l.setSpacing(6)

    if not sim_text:  # show pill "NO CELL"
        lbl = QLabel("NO CELL")
        lbl.setObjectName("SimPill")
        f = QtGui.QFont(w.font()); f.setBold(True)
        lbl.setFont(f)
        lbl.setAlignment(Qt.AlignVCenter)
        lbl.setStyleSheet(
            "#SimPill { background:#6b7280; color:#fff; padding:2px 8px; border-radius:8px; }"
        )
        l.addWidget(lbl)
    else:
        # number label
        num = QLabel(sim_text)
        num.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        l.addWidget(num, 1)

        # send button
        btn = QToolButton(w)
        btn.setIcon(QIcon(resource_path("icons/send.png")))
        btn.setToolTip(f"Send SMS to {sim_text}")
        btn.setAutoRaise(True)
        btn.setCursor(Qt.PointingHandCursor)
        btn.clicked.connect(lambda _=False, d=dev_id, to=sim_text: on_send_cb(d, to))
        l.addWidget(btn, 0)

    l.addStretch(1)
    return w

def _is_qualified_cell_row(d: dict) -> bool:
    """
    Keep only real cellular rows:
      - interface starts with 'Cellular'
      - IP is assigned (not 'unassigned' / empty)
      - link is up (status == 'up' AND protocol contains 'up')
    """
    name = (d.get("interface") or d.get("name") or "").lower()
    if not name.startswith("cellular"):
        return False
    ip = (d.get("ip") or d.get("ip_addr") or "").strip().lower()
    if not ip or ip == "unassigned":
        return False
    status   = (d.get("status") or "").strip().lower()
    protocol = (d.get("protocol") or "").strip().lower()
    return status == "up" and "up" in protocol

# ---------- Crypto for SSH password ----------
# --- Feature flags ---
ALLOW_SSH_HUB_DETECT = True   # <- set True only if you can SSH to devices
HUB_PROBE_ALLOWLIST = {
    "192.168.18.43",
    # add/remove as needed
}

# --- Debug flag for Tunnel tab ---
DEBUG_TUNNELS = True

def _show_text_dialog(parent, title: str, text: str):
    from PyQt5 import QtWidgets
    d = QtWidgets.QDialog(parent)
    d.setWindowTitle(title)
    d.resize(900, 600)
    v = QtWidgets.QVBoxLayout(d)
    te = QtWidgets.QPlainTextEdit(d)
    te.setReadOnly(True)
    te.setPlainText(text)
    v.addWidget(te)
    bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close, d)
    bb.rejected.connect(d.reject); bb.accepted.connect(d.accept)
    v.addWidget(bb)
    d.exec_()

FERNET_KEY = b"hZtFdYoCGy2E68Fz46zqFbW4NHnSLmP4F78w_BV9mN4="
fernet = Fernet(FERNET_KEY)

def encrypt_password(password):
    return fernet.encrypt(password.encode())

def decrypt_password(encrypted):
    if encrypted is None:
        return None
    if isinstance(encrypted, memoryview):
        encrypted = encrypted.tobytes()
    elif isinstance(encrypted, bytearray):
        encrypted = bytes(encrypted)
    elif isinstance(encrypted, str):
        encrypted = encrypted.encode("utf-8")
    return fernet.decrypt(encrypted).decode("utf-8")

# inside class CiscoSMSMonitorApp:
# --- Helpers to add inside CiscoSMSMonitorApp -------------------------------

def _col_index(self, header_text: str, default: int = -1) -> int:
    """Return the column index for a header (case-insensitive), or default."""
    try:
        for c in range(self.deviceTable.columnCount()):
            item = self.deviceTable.horizontalHeaderItem(c)
            if item and item.text().strip().lower() == header_text.strip().lower():
                return c
    except Exception:
        pass
    return default

# top-level helper (NOT a method)
def _make_cell_spinner(parent) -> QLabel:
    lbl = QLabel(parent)
    mv = QMovie(resource_path("spinner.gif"))
    mv.setScaledSize(QSize(18, 18))
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setMovie(mv)
    # keep a reference so GC doesn't stop it
    lbl.movie = mv
    mv.start()
    return lbl

def choose_sms_iface(ip: str) -> str:
    """
    Return CLI prefix like 'cellular 0/0/0' for the best/active cellular iface.
    Falls back to 0/0/0 if nothing found.
    """
    try:
        infos = list_cellular_interfaces(ip)  # [{'name':'Cellular0/0/0', 'status':'Registered', ...}, ...]
        if not infos:
            return "cellular 0/0/0"
        # Prefer Registered/Connected/UP and with an IP/protocol if possible
        def score(i):
            s = (i.get("status") or "").lower()
            p = (i.get("protocol") or "").lower()
            ipset = 1 if i.get("ip") else 0
            # higher is better
            return (
                10 if "registered" in s or "normal service" in s or "attached" in s else 0
            ) + (5 if "connected" in s or "up" in s else 0) + (2 if "ipv4" in p or "ipv6" in p else 0) + ipset
        best = max(infos, key=score)
        name = (best.get("name") or "Cellular0/0/0").strip()
        # Router CLI expects lowercase 'cellular' + slot
        slot = name.replace("Cellular", "").strip()
        return f"cellular {slot}"
    except Exception:
        return "cellular 0/0/0"

def update_sim_for_device(device_id: int, sim_number: str):
    """Set SIM for all cellular rows of a device (idempotent)."""
    db = get_db_config()
    conn = mysql.connector.connect(**db)
    cur = conn.cursor()
    cur.execute("UPDATE device_cellular SET sim=%s WHERE device_id=%s", (sim_number, device_id))
    conn.commit()
    cur.close(); conn.close()

# --- Router facts (hostname / IOS / modem firmware) -------------------------

def _parse_hostname(ver_text: str, run_cfg_line: str) -> str:
    m = re.search(r"(?mi)^\s*hostname\s+([A-Za-z0-9_.-]+)\s*$", run_cfg_line or "")
    if m: return m.group(1).strip()
    m = re.search(r"(?m)^\s*([A-Za-z0-9_.-]+)\s+uptime is\b", ver_text or "")
    return (m.group(1).strip() if m else "")

def _parse_ios_version(ver_text: str) -> str:
    t = ver_text or ""
    m = re.search(r"(?i)Cisco IOS XE Software,\s*Version\s*([0-9A-Za-z.\(\)-]+)", t)
    if m: return m.group(1)
    m = re.search(r"(?i)Cisco IOS Software.*Version\s*([0-9A-Za-z.\(\)-]+)", t)
    if m: return m.group(1)
    m = re.search(r"(?i)\bVersion\s*([0-9A-Za-z.\(\)-]+)", t)
    return m.group(1) if m else ""

def _parse_cell_fw(*texts: str) -> str:
    for s in texts:
        if not s: continue
        m = re.search(r"(?i)\b(?:Modem\s+)?Firmware(?:\s+|-)Version\s*[:=]\s*([^\r\n]+)", s)
        if m: return m.group(1).strip()
        m = re.search(r"(?i)\bFirmware\s*[:=]\s*([^\r\n]+)", s)
        if m: return m.group(1).strip()
    return ""

def fetch_latest_sim_from_db(device_id: int) -> str:
    """Return the newest non-empty SIM for a device from device_cellular."""
    db = get_db_config()
    conn = mysql.connector.connect(**db)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT sim
            FROM device_cellular
            WHERE device_id = %s AND COALESCE(sim, '') <> ''
            ORDER BY id DESC
            LIMIT 1
        """, (device_id,))
        row = cur.fetchone()
        return (row[0] or "").strip() if row else ""
    finally:
        try: cur.close()
        except: pass
        conn.close()

def parse_sms_view_all_for_dialog(text: str):
    """
    Parse Cisco 'lte sms view all' output into a list of dicts with keys:
    ID, Time, From, Size, Content.
    Works with CRLF and dashed separators.
    """
    if not text:
        return []

    # One entry looks like:
    # SMS ID: N
    # TIME: yyyy-mm-dd hh:mm:ss
    # FROM: <sender>
    # SIZE: n
    # <content possibly quoted>
    # ----- (separator) OR end of text
    pattern = re.compile(
        r"SMS ID:\s*(\d+)\s*[\r\n]+"
        r"TIME:\s*([^\r\n]+)\s*[\r\n]+"
        r"FROM:\s*([^\r\n]+)\s*[\r\n]+"
        r"SIZE:\s*(\d+)\s*[\r\n]+"
        r"(.*?)(?:\r?\n-+\r?\n|$)",   # content until dashed line or end
        re.S
    )

    entries = []
    for m in pattern.finditer(text):
        sms_id, tm, frm, sz, body = m.groups()
        body = (body or "").strip()

        # If body is wrapped in double quotes on both ends, strip them
        if len(body) >= 2 and body[0] == '"' and body[-1] == '"':
            body = body[1:-1]

        entries.append({
            "ID": sms_id,
            "Time": tm,
            "From": frm,
            "Size": sz,
            "Content": body,
        })
    return entries

def parse_sms_view_all(text: str):
        """
        Parse 'lte sms view all' output into a list of dicts.
        Accepts both single- and multi-entry blocks.
        """
        if not text:
            return []

        blocks = [b.strip() for b in re.split(r"\n\s*\n", text) if b.strip()]
        entries = []
        for b in blocks:
            m_id   = re.search(r"SMS ID:\s*(\d+)", b)
            m_time = re.search(r"TIME:\s*([^\n]+)", b)
            m_from = re.search(r"FROM:\s*([^\n]+)", b)
            m_size = re.search(r"SIZE:\s*(\d+)", b)
            m_body = re.search(r"SIZE:\s*\d+\s*(.+)", b, re.DOTALL)

            # tolerate 'view all' outputs that may omit body
            entries.append({
                "id":   m_id.group(1)   if m_id else "",
                "time": m_time.group(1) if m_time else "",
                "from": m_from.group(1) if m_from else "",
                "size": m_size.group(1) if m_size else "",
                "body": (m_body.group(1).strip() if m_body else "").strip('"')
            })
        return entries

def update_device_facts_in_db(*, device_id=None, ip=None, hostname=None, ios=None, firmware=None):
    try:
        db_config = get_db_config()
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        if device_id is not None:
            cur.execute("""
                UPDATE devices
                   SET hostname=%s, ios_version=%s, modem_firmware=%s
                 WHERE id=%s
            """, (hostname, ios, firmware, int(device_id)))
        elif ip:
            cur.execute("""
                UPDATE devices
                   SET hostname=%s, ios_version=%s, modem_firmware=%s
                 WHERE ip=%s
            """, (hostname, ios, firmware, ip))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        print(f"⚠️ update_device_facts_in_db: {e}")

def get_router_facts(ip: str, *, timeout: int = 10) -> dict:
    """Return {'hostname','ios','firmware'} via SSH; best-effort."""
    facts = {"hostname": "", "ios": "", "firmware": ""}
    if not is_device_online(ip):
        return facts
    username, password = get_ssh_credentials()
    if not (username and password):
        return facts
    try:
        cli = ssh_connect_resilient(ip, username, password,
                                    conn_timeout=8, banner_timeout=25, auth_timeout=20, tries=2)
        sh = cli.invoke_shell(); sh.settimeout(timeout)
        time.sleep(0.3)
        if sh.recv_ready(): _ = sh.recv(65535)
        _shell_send_and_read(sh, "terminal length 0", sleep=0.15, drain_loops=6)
        ver   = _shell_send_and_read(sh, "show version", sleep=0.35, drain_loops=10)
        hline = _shell_send_and_read(sh, "show running-config | include ^hostname ", sleep=0.25, drain_loops=6)
        brief = _shell_send_and_read(sh, "show ip interface brief", sleep=0.3, drain_loops=8)

        facts["hostname"] = _parse_hostname(ver, hline)
        facts["ios"]      = _parse_ios_version(ver)

        slot = _find_cellular_slot_from_brief(brief)
        if slot:
            hw  = _shell_send_and_read(sh, f"show cellular {slot} hardware", sleep=0.3, drain_loops=10)
            all_= _shell_send_and_read(sh, f"show cellular {slot} all",      sleep=0.35, drain_loops=12)
            facts["firmware"] = _parse_cell_fw(hw, all_)
    except Exception as e:
        print(f"⚠️ get_router_facts({ip}): {e}")
    finally:
        try: sh.close()
        except Exception: pass
        try: cli.close()
        except Exception: pass
    return facts

def ssh_connect_resilient(ip, username, password,
                          conn_timeout=8, banner_timeout=25, auth_timeout=20,
                          tries=3, sleep_between=0.8):
    last_err = None
    for attempt in range(1, tries + 1):
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(
                ip,
                username=username,
                password=password,
                look_for_keys=False,
                allow_agent=False,
                timeout=conn_timeout,
                banner_timeout=banner_timeout,
                auth_timeout=auth_timeout,
            )
            return cli
        except (paramiko.ssh_exception.SSHException,
                paramiko.ssh_exception.NoValidConnectionsError,
                OSError) as e:
            last_err = e
            try: cli.close()
            except: pass
            if isinstance(e, paramiko.ssh_exception.SSHException) and "banner" in str(e).lower():
                banner_timeout = min(banner_timeout + 10, 60)
                conn_timeout   = min(conn_timeout + 2, 20)
            time.sleep(sleep_between)
    raise last_err

# ---------- Fast helpers your loader uses ----------

# (Optional but recommended) tiny TTL cache to avoid hammering devices
_CELLULAR_CACHE = {}   # ip -> (ts, present_bool)
_REGISTER_CACHE = {}   # ip -> (ts, registered_bool)
_CACHE_TTL_SEC = 120   # 2 minutes

def has_cellular_interface(ip: str, timeout: int = 6) -> bool:
    """
    True only if at least one Cellular interface is UP and has a real IP.
    """
    import time, re, paramiko
    now = time.time()
    hit = _CELLULAR_CACHE.get(ip)
    if hit and (now - hit[0] <= _CACHE_TTL_SEC):
        return hit[1]

    if not is_device_online(ip):
        _CELLULAR_CACHE[ip] = (now, False); return False

    username, password = get_ssh_credentials()
    if not username or not password:
        _CELLULAR_CACHE[ip] = (now, False); return False

    ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=username, password=password,
                    look_for_keys=False, allow_agent=False,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
        _, stdout, _ = ssh.exec_command("show ip interface brief")
        out = stdout.read().decode(errors="ignore")
    except Exception:
        _CELLULAR_CACHE[ip] = (now, False); return False
    finally:
        try: ssh.close()
        except: pass

    ok = False
    for line in out.splitlines():
        if not re.match(r"^\s*Cellular[\d/]+\b", line, re.I):
            continue
        cols = re.split(r"\s+", line.strip())
        name     = cols[0] if len(cols) > 0 else ""
        ipaddr   = cols[1] if len(cols) > 1 else ""
        status   = cols[4].lower() if len(cols) > 4 else ""
        protocol = cols[-1].lower() if cols else ""
        ip_good  = ipaddr and ipaddr.lower() != "unassigned"
        link_up  = (status == "up") and ("up" in protocol)
        if name.lower().startswith("cellular") and ip_good and link_up:
            ok = True; break

    _CELLULAR_CACHE[ip] = (now, ok)
    return ok

_ipv4_re = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
)
# Robust IPv4 matcher (0–255 in each octet)
_IPV4_PATTERN = r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"

# Define _ipv4_re if it doesn't exist yet (safe even if you already had one)
try:
    _ipv4_re
except NameError:
    _ipv4_re = re.compile(_IPV4_PATTERN)

def map_to_lan(ip: str) -> str:
    """
    Map NBMA (e.g. 172.16.1.205) -> LAN (192.168.205.1).
    Rule: swap the last two octets, and prefix with 192.168.
    If the IP is already 192.168.X.Y, return it unchanged.
    """
    try:
        a, b, c, d = ip.split(".")
    except ValueError:
        return ip  # not IPv4-ish, bail

    # If it's already on the LAN scheme, don't touch it
    if a == "192" and b == "168":
        return ip

    # NBMA -> LAN: 172.16.c.d  ==>  192.168.d.c
    return f"192.168.{d}.{c}"

def note_recent_sender(lan_ip: str):
    """Remember that 'lan_ip' just sent an SMS (now)."""
    with _RECENT_LOCK:
        _RECENT_SENDERS.append((lan_ip, time.time()))

def is_device_register(ip: str, *, timeout: int = 8) -> bool:
    """
    True if this router has our machine set as a 'logging host' (syslog destination).
    Uses a short cache to keep UI snappy.
    """
    import time
    now = time.time()
    hit = _REGISTER_CACHE.get(ip)
    if hit and (now - hit[0] <= _CACHE_TTL_SEC):
        return hit[1]

    if not is_device_online(ip):
        _REGISTER_CACHE[ip] = (now, False)
        return False

    username, password = get_ssh_credentials()
    if not username or not password:
        _REGISTER_CACHE[ip] = (now, False)
        return False

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=username, password=password,
                    look_for_keys=False, allow_agent=False,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
        # Check only the lines we care about; fast and safe
        cmd = r"show running-config | include ^logging host "
        _, stdout, _ = ssh.exec_command(cmd)
        output = stdout.read().decode(errors="ignore")
    except Exception:
        _REGISTER_CACHE[ip] = (now, False)
        return False
    finally:
        try: ssh.close()
        except: pass

    # Parse configured syslog hosts
    hosts = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("logging host"):
            continue
        m = _ipv4_re.search(line)
        if m:
            hosts.append(m.group(0))

    # our PC's IP as seen by the routers (used elsewhere in your app)
    my_ip = get_ip_address()
    registered = my_ip in hosts
    _REGISTER_CACHE[ip] = (now, registered)
    return registered

def run_cmd_fresh(ip: str, username: str, password: str, cmd: str,
                  timeout: int = 12, prompt_end=(b'#', b'>')) -> str:
    ssh = ssh_connect_resilient(ip, username, password,
                                conn_timeout=8, banner_timeout=25, auth_timeout=20, tries=3)
    
    chan = ssh.invoke_shell(width=200, height=50)
    chan.settimeout(timeout)

    def _drain_once():
        data = b''
        try:
            while chan.recv_ready():
                data += chan.recv(65535)
        except Exception:
            pass
        return data

    def _send(line: str):
        chan.send(line + '\r')

    # settle banner
    time.sleep(0.3)
    _ = _drain_once()

    # disable paging
    _send('terminal length 0')
    time.sleep(0.1)
    _ = _drain_once()

    # run command
    _send(cmd)

    buf = bytearray()
    last = time.time()
    more_pat = re.compile(br'--More--|\(q\)uit', re.I)

    try:
        while True:
            if chan.recv_ready():
                chunk = chan.recv(65535)
                if not chunk:
                    break
                buf.extend(chunk)
                last = time.time()

                tail = bytes(buf[-256:])
                # handle pager
                if more_pat.search(tail):
                    chan.send(' ')  # advance page
                    continue

                # stop when prompt appears at end of a line
                tail_stripped = tail.rstrip()
                if any(tail_stripped.endswith(pe) for pe in prompt_end):
                    break
            else:
                if time.time() - last > timeout:
                    break
                time.sleep(0.05)
    finally:
        try:
            chan.close()
        except Exception:
            pass
        try:
            ssh.close()
        except Exception:
            pass

    # clean echoes & prompt
    out = buf.decode(errors='ignore')
    cleaned = []
    for ln in out.splitlines():
        s = ln.strip()
        if not s:
            continue
        if s.startswith('terminal length 0') or s.startswith(cmd):
            continue
        if (s.endswith('#') or s.endswith('>')) and ' ' not in s and len(s) <= 80:
            continue
        cleaned.append(ln)
    return '\n'.join(cleaned).strip()

def _merge_cell_details(old_list, new_list):
    """
    Merge by interface; prefer new IMEI/IMSI/ICCID if provided.
    Later runtime fields (ip/status/protocol/apn) always overwritten.
    """
    by_if = {d.get("interface",""): dict(d) for d in (old_list or [])}
    for nd in (new_list or []):
        key = nd.get("interface","")
        cur = by_if.get(key, {})
        # always refresh runtime fields
        for k in ("ip","status","protocol","apn","sim"):
            cur[k] = nd.get(k, "")
        # keep non-empty IDs
        for k in ("imsi","imei","iccid"):
            if nd.get(k):
                cur[k] = nd[k]
        by_if[key] = cur
    # filter to qualified rows only
    return [d for d in by_if.values() if _is_qualified_cell_row(d)]

def cleanup_ineligible_cellular_rows():
    db = get_db_config()
    conn = mysql.connector.connect(**db)
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT DISTINCT device_id FROM device_cellular")
    device_ids = [r["device_id"] for r in cur.fetchall()]
    cur.close(); conn.close()

    for dev_id in device_ids:
        rows = get_device_cellular(dev_id)
        keep = []
        for r in rows:
            d = {
                "interface": r["interface"], "ip": r["ip_addr"],
                "status": r["status"], "protocol": r["protocol"],
                "imsi": r["imsi"], "imei": r["imei"], "iccid": r["iccid"],
                "apn": r["apn"], "sim": r.get("sim") or ""
            }
            if _eligible_detail(d):
                keep.append(d)
        replace_device_cellular(dev_id, keep)

# ---------- DB config ----------
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

# ---------- SSH creds ----------
def get_ssh_credentials():
    try:
        db_config = get_db_config()
        if not db_config:
            return None, None
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password FROM user_ssh ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        cursor.close(); conn.close()

        if not row:
            print("⚠️ No SSH credentials found in user_ssh.")
            return None, None

        username = row[0]
        try:
            password = decrypt_password(row[1])
        except Exception as e:
            print(f"⚠️ Failed to decrypt SSH password: {e}")
            return None, None
        return username, password
    except Exception as e:
        print(f"⚠️ Failed to load SSH credentials: {e}")
        return None, None

def _score_iface(d: dict) -> tuple:
    ip = (d.get("ip") or "").strip().lower()
    has_ip = bool(ip and ip != "unassigned")
    status = (d.get("status") or "").lower()
    proto  = (d.get("protocol") or "").lower()
    link_up = ("up" in proto) or (status == "up")
    return (1 if has_ip else 0, 1 if link_up else 0, d.get("interface",""))

def _is_eligible_cellular(d: dict) -> bool:
    """
    Only keep real/usable cellular rows:
      1) interface name starts with 'Cellular'
      2) has an IP (not 'unassigned' / empty)
      3) link is up (Status == 'up' OR Protocol contains 'up')
    """
    if not (d.get("interface","").lower().startswith("cellular")):
        return False
    ip = (d.get("ip") or "").strip().lower()
    if not ip or ip == "unassigned":
        return False
    status = (d.get("status") or "").strip().lower()
    proto  = (d.get("protocol") or "").strip().lower()
    link_up = (status == "up") or ("up" in proto)
    return link_up

def update_device_primary_cellular(device_id: int, best: dict, apn: str = ""):
    db = get_db_config()
    conn = mysql.connector.connect(**db)
    cur = conn.cursor()
    cur.execute("""
        UPDATE devices
           SET apn=%s     -- no more sim/imsi/imei/iccid here
         WHERE id=%s
    """, ((apn or best.get("apn") or None), device_id))
    conn.commit(); cur.close(); conn.close()

def badge_widget(text: str, bg="#6b7280", fg="#fff") -> QWidget:
    w = QWidget()
    l = QHBoxLayout(w); l.setContentsMargins(0, 0, 0, 0)
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"QLabel {{ background:{bg}; color:{fg}; padding:2px 6px; "
        f"border-radius:6px; font-weight:600; font-size:11px; }}"
    )
    l.addWidget(lbl); l.addStretch(1)
    return w

def get_device_cellular(device_id: int):
    db = get_db_config()
    conn = mysql.connector.connect(**db)
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, interface, ip_addr, status, protocol,
               imsi, imei, iccid, apn, sim, last_seen          -- ← sim
        FROM device_cellular
        WHERE device_id=%s
        ORDER BY interface
    """, (device_id,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return rows

def upsert_device_cellular(device_id: int, details: list):
    if not details:
        return
    db = get_db_config()
    conn = mysql.connector.connect(**db)
    cur = conn.cursor()
    sql = """
    INSERT INTO device_cellular
      (device_id, interface, ip_addr, status, protocol,
       imsi, imei, iccid, apn, sim, last_seen)                -- ← sim
    VALUES
      (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
    ON DUPLICATE KEY UPDATE
      ip_addr=VALUES(ip_addr),
      status=VALUES(status),
      protocol=VALUES(protocol),
      imsi=VALUES(imsi),
      imei=VALUES(imei),
      iccid=VALUES(iccid),
      apn=VALUES(apn),
      sim=VALUES(sim),                                        -- ← sim
      last_seen=NOW();
    """
    for d in details:
        ip_addr = (d.get("ip_addr") or d.get("ip") or "").strip() or None
        cur.execute(sql, (
            device_id,
            d.get("interface",""),
            ip_addr,
            d.get("status") or None,
            d.get("protocol") or None,
            d.get("imsi") or None,
            d.get("imei") or None,
            d.get("iccid") or None,
            d.get("apn") or None,
            d.get("sim") or None,                              # ← sim
        ))
    conn.commit()
    cur.close(); conn.close()

def _find_cellular_slot_from_brief(full_text: str) -> str:
    m = re.search(r"(?mi)^\s*Cellular\s*(\d+(?:/\d+){0,2})\b", full_text)
    if m:
        return m.group(1)
    m = re.search(r"(?mi)^\s*Cellular(\d+(?:/\d+){0,2})\b", full_text)
    return m.group(1) if m else ""

def _parse_apn(text: str) -> str:
    m = re.search(r"(?im)\bAPN\)?\s*[:=]\s*([A-Za-z0-9._:-]+)", text)
    if m: return m.group(1)
    m = re.search(r"(?im)^\s*apn\s+([A-Za-z0-9._:-]+)\b", text)
    if m: return m.group(1)
    m = re.search(r"(?im)Profile\s*1.*?\bAPN\b.*?([A-Za-z0-9._:-]+)", text)
    if m: return m.group(1)
    return ""

# ---------- Networking helpers ----------
def is_device_online(ip: str, port: int = 22, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

def _shell_send_and_read(shell, cmd, sleep=0.5, drain_loops=8):
    shell.send(cmd.rstrip() + "\n")
    time.sleep(sleep)
    out = ""
    for _ in range(drain_loops):
        chunk = ""
        while shell.recv_ready():
            chunk += shell.recv(65535).decode(errors="ignore")
        out += chunk
        if chunk == "":
            break
        time.sleep(0.15)
    return out

_ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ---------- Email (TrackIT queue) ----------
def get_email_config_from_db():
    try:
        db_config = get_db_config()
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT smtp_server, smtp_port, smtp_user, smtp_password, sender_email
            FROM email_config
            WHERE active = 1
            LIMIT 1
        """)
        config = cursor.fetchone()
        cursor.close(); conn.close()
        return config
    except Exception as e:
        print(f"❌ Error loading email config from DB: {e}")
        return None

def _is_real_ip(ip: str) -> bool:
    ip = (ip or "").strip().lower()
    return bool(ip) and ip != "unassigned"

def _eligible_detail(d: dict) -> bool:
    name = (d.get("interface") or d.get("name") or "").lower()
    stat = (d.get("status") or "").lower()
    proto = (d.get("protocol") or "").lower()
    return (
        name.startswith("cellular") and
        _is_real_ip(d.get("ip")) and
        ("up" in proto or stat == "up")
    )

def replace_device_cellular(device_id: int, details: list):
    # keep only real rows, then bail if nothing to update
    details = [d for d in (details or []) if _is_qualified_cell_row(d)]
    if not details:
        return  # ← Do nothing; preserves existing SIM/IDs

    db = get_db_config()
    conn = mysql.connector.connect(**db)
    cur = conn.cursor()
    cur.execute("DELETE FROM device_cellular WHERE device_id=%s", (device_id,))
    conn.commit()
    cur.close(); conn.close()

    upsert_device_cellular(device_id, details)

# ---------- Fast single-SSH probe ----------
def probe_device_fast(ip: str, timeout: int = 6):
    if not is_device_online(ip):
        return {"present": False, "has_cell": False, "register": False}

    username, password = get_ssh_credentials()
    if not username or not password:
        return {"present": False, "has_cell": False, "register": False}

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=username, password=password,
                    look_for_keys=False, allow_agent=False,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)

        sh = ssh.invoke_shell()
        time.sleep(0.3)
        if sh.recv_ready():
            _ = sh.recv(65535)

        def send(cmd):
            sh.send(cmd + "\n"); time.sleep(0.45)
            out = ""
            while sh.recv_ready():
                out += sh.recv(65535).decode(errors="ignore")
            return out

        brief = send("show ip interface brief")
        run = send("show running-config | include ^logging host ")
    except Exception:
        try: ssh.close()
        except: pass
        return {"present": False, "has_cell": False, "register": False}
    finally:
        try: ssh.close()
        except: pass

    present = False
    ip_assigned = False
    for line in brief.splitlines():
        if re.search(r"(?i)^\s*Cellular\d+(?:/\d+)*\b", line):
            present = True
            cols = re.split(r"\s+", line.strip())
            ip_col = cols[1] if len(cols) > 1 else ""
            if ip_col and ip_col.lower() != "unassigned":
                ip_assigned = True

    my_ip = get_ip_address()
    register = my_ip in re.findall(_ipv4_re, run)
    return {"present": present, "has_cell": (present and ip_assigned), "register": bool(register)}

def get_ip_address() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

# ---------- Email sending ----------
def send_email(sms_details, emailTo):
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
📩 New SMS Received
--------------------------------------
ID:   {sms_details['ID']}
Time: {sms_details['Time']}
From: {sms_details['From']}
Size: {sms_details['Size']}

Message:
{sms_details['Content']}
--------------------------------------
"""
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(config["smtp_server"], config["smtp_port"])
        if config["smtp_user"] and config["smtp_password"]:
            server.login(config["smtp_user"], config["smtp_password"])
        server.sendmail(config["sender_email"], emailTo, msg.as_string())
        server.quit()
        print("✅ Email notification queued/sent.")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# put near other Qt classes
class DetectAllRunner(QtCore.QObject):
    step_started = pyqtSignal(str)
    step_done    = pyqtSignal(str, bool, object)   # name, ok, payload
    finished     = pyqtSignal()

    def __init__(self, dev: dict, parent=None):
        super().__init__(parent)
        self.dev = dev
        self._cancel = False

    @pyqtSlot()
    def run(self):
        ip = self.dev.get("ip", "")
        try:
            username, password = get_ssh_credentials()
            if not (username and password):
                # no creds → still “finish” the flow
                self.step_done.emit("init", False, "No SSH credentials")
                self.finished.emit(); return
        except Exception as e:
            self.step_done.emit("init", False, str(e))
            self.finished.emit(); return

        # ---- STEP 1: Gateway ----
        if not self._cancel:
            self.step_started.emit("Gateway")
            ok, payload = False, None
            try:
                gw_ip, gw_if = detect_default_gateway(ip, username, password, vrf=None)
                gw = f"{gw_ip} ({gw_if})" if gw_ip and gw_if else (gw_ip or "")
                if gw:
                    ok, payload = True, gw
                    update_device_in_db({**self.dev, "gateway": gw, "cellular_details": []})
                else:
                    payload = "Gateway of last resort not set"
            except Exception as e:
                payload = f"{type(e).__name__}: {e}"
            self.step_done.emit("Gateway", ok, payload)

        # ---- STEP 2: Cellular ----
        shown = []
        best  = {}
        if not self._cancel:
            self.step_started.emit("Cellular")
            ok, payload = False, None
            try:
                details = fetch_all_cellular_details(ip, timeout=8)  # per-step timeout
                shown = [d for d in (details or []) if _is_qualified_cell_row(d)]
                if shown:
                    replace_device_cellular(self.dev["id"], shown)  # persist NOW
                    try:
                        best = max(shown, key=_score_iface)
                    except ValueError:
                        best = shown[0]
                    ok, payload = True, f"{len(shown)} interface(s)"
                else:
                    payload = "No eligible cellular interfaces"
            except Exception as e:
                payload = f"{type(e).__name__}: {e}"
            self.step_done.emit("Cellular", ok, payload)

        # ---- STEP 3: APN ----
        apn = None
        if not self._cancel:
            self.step_started.emit("APN")
            ok, payload = False, None
            try:
                # strict SSH timeouts; safe reads
                cli = paramiko.SSHClient()
                cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                cli.connect(
                    ip, username=username, password=password,
                    look_for_keys=False, allow_agent=False,
                    timeout=6, banner_timeout=10, auth_timeout=8
                )
                sh = cli.invoke_shell(); sh.settimeout(6)
                time.sleep(0.4)
                if sh.recv_ready(): _ = sh.recv(65535)

                def send(cmd): return _shell_send_and_read(sh, cmd, sleep=0.35, drain_loops=8)

                brief = send("show ip interface brief")
                slot  = _find_cellular_slot_from_brief(brief)
                big = ""
                if slot:
                    for cmd in (
                        f"show cellular {slot} profile",
                        f"show cellular {slot} lte profile",
                        f"show cellular {slot} all",
                        f"show running-config | section ^cellular {slot}",
                        "show running-config | include apn",
                    ):
                        big += "\n--- " + cmd + " ---\n" + send(cmd)

                try: sh.close()
                except: pass
                try: cli.close()
                except: pass

                apn = _parse_apn(big) or None
                if apn:
                    # write APN now; also update device primary if we have a 'best'
                    update_device_in_db({**self.dev, "apn": apn, "cellular_details": []})
                    if best:
                        update_device_primary_cellular(self.dev["id"], best, apn)
                    ok, payload = True, apn
                else:
                    payload = "APN not found"
            except Exception as e:
                payload = f"{type(e).__name__}: {e}"
            self.step_done.emit("APN", ok, payload)

        # Finalize: if there was a best cellular iface and no APN change yet,
        # still ensure device primary fields are consistent.
        try:
            if best and not apn:
                update_device_primary_cellular(self.dev["id"], best, self.dev.get("apn") or "")
        except Exception:
            pass

        self.finished.emit()

    def cancel(self):
        self._cancel = True

class DetectAllProgress(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Detect All")
        self.setModal(True)
        self.setFixedWidth(420)
        v = QVBoxLayout(self)

        self.l_status = QLabel("Starting…")
        self.l_gw  = QLabel("Gateway: pending")
        self.l_cell= QLabel("Cellular: pending")
        self.l_apn = QLabel("APN: pending")
        for lbl in (self.l_status, self.l_gw, self.l_cell, self.l_apn):
            v.addWidget(lbl)

        self.btnCancel = QPushButton("Cancel next steps")
        v.addWidget(self.btnCancel)

    def show_step_started(self, name):
        self.l_status.setText(f"Running: {name} …")

    def show_step_done(self, name, ok, payload):
        mark = "✅" if ok else "⚠️"
        text = f"{name}: {mark} {payload if isinstance(payload, str) else ''}"
        if name == "Gateway":  self.l_gw.setText(text)
        if name == "Cellular": self.l_cell.setText(text)
        if name == "APN":      self.l_apn.setText(text)
        self.l_status.setText("Ready for next step…")

# ---------- UI helpers ----------
class LoadingSpinner(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background-color: rgba(255, 255, 255, 180);")
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        self.label = QLabel()
        self.label.setAlignment(Qt.AlignCenter)
        self.movie = QMovie(resource_path("spinner.gif"))
        self.movie.setScaledSize(QSize(64, 64))
        self.label.setMovie(self.movie)
        layout.addWidget(self.label)
        self.setVisible(False)
    def start(self):
        self.setVisible(True); self.movie.start()
    def stop(self):
        self.setVisible(False); self.movie.stop()

def make_device_cell(name: str, is_hub: bool, has_cellular: bool, base_font=None) -> QWidget:
    w = QWidget()
    lay = QHBoxLayout(w); lay.setContentsMargins(6, 0, 0, 0); lay.setSpacing(6)

    if base_font is None:
        # safest: match exactly what the table uses to paint items
        base_font = QtWidgets.QApplication.font("QTableView")

    def pill(text, bg, fg="#fff"):
        lbl = QLabel(text); lbl.setObjectName("HubPill")
        f = QtGui.QFont(base_font); f.setBold(True)
        lbl.setFont(f)
        lbl.setAlignment(Qt.AlignVCenter)
        lbl.setStyleSheet("#HubPill { background:%s; color:%s; padding:2px 6px; border-radius:6px; }" % (bg, fg))
        return lbl

    if is_hub:
        lay.addWidget(pill("HUB", "#2563eb"))

    name_lbl = QLabel(("  " + name) if is_hub else name)
    name_lbl.setObjectName("DeviceNameLabel")
    name_lbl.setFont(base_font)                               # ← exact same font as items
    name_lbl.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
    name_lbl.setWordWrap(False)
    name_lbl.setStyleSheet("#DeviceNameLabel { background:transparent; color:palette(text); padding:0; margin:0; }")

    lay.addWidget(name_lbl); lay.addStretch(1)
    return w

def create_status_label(status):
    label = QLabel()
    if status == "Online":
        text = '<span style="color: black;">Online </span><span style="color: #34d399; font-size: 20px;">●</span>'
    elif status == "Not Register":
        text = '<span style="color: black;">Not Register </span><span style="color: #708090; font-size: 20px;">●</span>'
    else:
        text = '<span style="color: black;">Offline </span><span style="color: #f87171; font-size: 20px;">●</span>'
    label.setText(text); label.setAlignment(Qt.AlignCenter)
    return label

# ---------- SMS parsing helpers ----------
def is_phone_number(s: str) -> bool:
    return bool(re.fullmatch(r"\+?\d{7,15}", s))

def is_hex_string(s: str) -> bool:
    try:
        int(s, 16)
        return len(s) % 2 == 0
    except ValueError:
        return False

def semi_octet_decode(hexstr: str) -> str:
    digits = ""
    for i in range(0, len(hexstr), 2):
        digits += hexstr[i+1] + hexstr[i]
    return digits.rstrip("F")

def gsm7_decode(hexstr: str) -> str:
    bits = ""
    for i in range(0, len(hexstr), 2):
        bits += bin(int(hexstr[i:i+2], 16))[2:].zfill(8)[::-1]
    septets = [bits[i:i+7][::-1] for i in range(0, len(bits), 7)]
    septets = [s for s in septets if len(s) == 7]
    decoded = ""
    for s in septets:
        val = int(s, 2)
        decoded += chr(val) if 32 <= val <= 126 else "?"
    return decoded.strip("?")

def gsm7_unpack(hexstr):
    swapped = "".join([hexstr[i+1] + hexstr[i] for i in range(0, len(hexstr), 2)])
    data = bytes.fromhex(swapped)
    septets, carry, carry_bits = [], 0, 0
    for b in data:
        val = ((b << carry_bits) & 0x7F) | carry
        septets.append(val)
        carry = b >> (7 - carry_bits)
        carry_bits += 1
        if carry_bits == 7:
            septets.append(carry)
            carry = 0
            carry_bits = 0
    text = "".join(chr(s) for s in septets if 32 <= s <= 126)
    return text

def normalize_sender(sender: str) -> str:
    if re.fullmatch(r"\+?\d{6,15}", sender):
        return sender
    if re.fullmatch(r"[0-9A-Fa-f]+", sender):
        try:
            num = semi_octet_decode(sender)
            if re.fullmatch(r"\d{6,15}", num):
                return num
            text = gsm7_decode(sender)
            return text if text else sender
        except Exception:
            return sender
    return sender

# ---------- Device/DB ----------
def set_device_hub_flag(device_id: int, is_hub: bool) -> int:
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute("UPDATE devices SET is_hub=%s WHERE id=%s", (1 if is_hub else 0, device_id))
    affected = cur.rowcount
    conn.commit()
    print(f"[HUB-FLAG] set is_hub={1 if is_hub else 0} for id={device_id} (affected={affected})")
    cur.execute("SELECT id, name, IFNULL(is_hub,0) FROM devices WHERE id=%s", (device_id,))
    row = cur.fetchone()
    print(f"[HUB-FLAG] readback -> {row}")
    cur.close(); conn.close()
    return affected

def _extract_sms_body(raw: str) -> str:
        """
        Cisco '... sms view <id>' output → return just the message text.
        Works for formats like:
        SMS ID: 13
        TIME: 25-11-03 10:24:28
        FROM: 61403352637
        SIZE: 19
        "sent from 206 (1)"
        Also copes with bodies that aren't quoted or are multi-line.
        """
        if not raw:
            return ""

        txt = raw.strip()

        # 1) Common case: quoted body on the next line after SIZE:
        m = re.search(r"SIZE:\s*\d+.*?\n(.*)$", txt, flags=re.I | re.S)
        body = (m.group(1).strip() if m else "")

        # 2) If not captured, try generic quoted content anywhere:
        if not body:
            m = re.search(r'"([^"]+)"', txt, flags=re.S)
            if m:
                body = m.group(1).strip()

        # 3) If still empty, try "Content:" style:
        if not body:
            m = re.search(r"CONTENT\s*:\s*(.*)$", txt, flags=re.I | re.S)
            if m:
                body = m.group(1).strip()

        # Cleanup: remove dashed footers and collapse whitespace
        body = re.sub(r"-{3,}.*$", "", body, flags=re.S)
        body = re.sub(r"\s+", " ", body).strip()
        return body

def _parse_msisdn(text: str) -> str:
    # MSISDN, MDN, Phone number, Line number: accept + and digits
    m = re.search(r"(?im)^\s*(?:MSISDN|MDN|Phone\s*Number|Line\s*Number)\s*[:=]\s*([+\d]{6,20})\b", text)
    return m.group(1) if m else ""

def load_devices_from_db():
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.name, d.ip, d.gateway, d.apn, d.email, d.id, IFNULL(d.is_hub,0),
               IFNULL(d.hostname,''), IFNULL(d.ios_version,''), IFNULL(d.modem_firmware,'')
        FROM devices d
    """)
    rows = cursor.fetchall()
    conn.close()

    devices = []
    for row in rows:
        name, ip, gateway, apn, email, dev_id, is_hub, hostname, ios, fw = row

        online = is_device_online(ip)

        try:
            cells = get_device_cellular(dev_id)
        except Exception:
            cells = []

        eligible = []
        for r in cells:
            d = {
                "interface": r["interface"],
                "ip": r["ip_addr"],
                "status": r["status"],
                "protocol": r["protocol"],
                "imsi": r["imsi"],
                "imei": r["imei"],
                "iccid": r["iccid"],
                "apn": r["apn"],
                "sim": r.get("sim") or "",
            }
            if _is_qualified_cell_row(d):
                eligible.append(d)

        has_cell = bool(eligible)
        try:
            best = max(eligible, key=_score_iface) if eligible else {}
        except ValueError:
            best = eligible[0] if eligible else {}

        sim_for_ui   = (best.get("sim") or "")
        iccid_for_ui = (best.get("iccid") or "")  # ← NEW

        register = is_device_register(ip) if (online and has_cell) else False
        status = (
            "Online"
            if (online and (register or not has_cell))
            else ("Offline" if not online else "Not Register")
        )

        devices.append({
            "name": name,
            "ip": ip,
            "gateway": gateway,
            "sim": sim_for_ui,
            "apn": apn,
            "iccid": iccid_for_ui,  # ← NEW (use this to display after APN)
            "email": email,
            "hostname": hostname,
            "ios_version": ios,
            "modem_firmware": fw,
            "lastSMS": "",
            "signal": 0,
            "status": status,
            "id": dev_id,
            "is_hub": bool(is_hub),
            "has_cellular": has_cell,
        })
    return devices

def update_device_in_db(device: dict):
    """
    Update the devices row and (optionally) cellular rows/SIM.
    - Only replaces device_cellular rows if non-empty 'cellular_details' are provided.
    - If a SIM text is supplied (device['sim']), persist it to device_cellular.sim.
    """
    db_config = get_db_config()

    # 1) Update main devices table
    conn = mysql.connector.connect(**db_config)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE devices
               SET apn=%s,
                   email=%s,
                   name=%s,
                   gateway=%s,
                   hostname=%s,
                   ios_version=%s,
                   modem_firmware=%s
             WHERE ip=%s
            """,
            (
                device.get("apn") or None,
                device.get("email") or None,
                device.get("name") or None,
                device.get("gateway") or None,
                device.get("hostname") or None,
                device.get("ios_version") or None,
                device.get("modem_firmware") or None,
                device["ip"],
            ),
        )
        conn.commit()
    finally:
        try: cur.close()
        except: pass
        conn.close()

    # 2) Replace device_cellular rows ONLY if caller passed new details
    dev_id = device.get("id")
    details = device.get("cellular_details", None)
    if dev_id and details:
        try:
            replace_device_cellular(dev_id, details)
        except Exception as e:
            print(f"⚠️ replace_device_cellular failed: {e}")

    # 3) If user typed a SIM in the dialog, persist it to device_cellular.sim
    sim_text = (device.get("sim") or "").strip()
    if dev_id and sim_text:
        try:
            # If you already have this helper, prefer it:
            # update_cellular_sim(dev_id, sim_text, prefer_iface=device.get("interface"))
            # Otherwise, use a minimal inline updater:
            _update_sim_for_device(dev_id, sim_text, prefer_iface=device.get("interface"))
        except Exception as e:
            print(f"⚠️ SIM update failed for device_id={dev_id}: {e}")


def replace_device_cellular(device_id: int, details: list):
    """
    Safely replace cellular rows for a device.
    - No-op if 'details' is empty (prevents accidental deletion when editing basic fields).
    - Inserts only 'qualified' rows.
    """
    # Reuse your existing qualifier if present; otherwise, use a conservative fallback.
    try:
        qual = _is_qualified_cell_row  # type: ignore[name-defined]
    except NameError:
        def qual(d: dict) -> bool:
            if not d: return False
            if not d.get("interface"): return False
            # keep row if any meaningful cellular field is present
            keys = ("ip_addr", "status", "protocol", "imsi", "imei", "iccid", "apn", "sim")
            return any((d.get(k) or "").strip() for k in keys)

    rows = [r for r in (details or []) if qual(r)]
    if not rows:
        # Nothing to replace → keep existing DB rows intact
        return

    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    try:
        cur = conn.cursor()
        # purge and re-insert only when we actually have rows
        cur.execute("DELETE FROM device_cellular WHERE device_id=%s", (device_id,))
        conn.commit()

        ins = (
            "INSERT INTO device_cellular "
            "(device_id, interface, ip_addr, status, protocol, imsi, imei, iccid, apn, sim, modem_firmware, last_seen) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, NOW())"
        )
        for r in rows:
            cur.execute(
                ins,
                (
                    device_id,
                    r.get("interface") or "",
                    r.get("ip_addr") or "unassigned",
                    r.get("status") or "",
                    r.get("protocol") or "",
                    r.get("imsi") or "",
                    r.get("imei") or "",
                    r.get("iccid") or "",
                    r.get("apn") or "",
                    r.get("sim") or "",
                    r.get("modem_firmware") or "",
                ),
            )
        conn.commit()
    finally:
        try: cur.close()
        except: pass
        conn.close()


def _update_sim_for_device(device_id: int, sim_text: str, prefer_iface: str | None = None):
    """
    Minimal inline SIM updater for device_cellular.sim.
    - If prefer_iface exists, update that row.
    - Else update the 'best' row (has IP, then status up, newest).
    - If no row exists, create a minimal one.
    """
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    try:
        cur = conn.cursor()

        row_id = None
        if prefer_iface:
            cur.execute(
                "SELECT id FROM device_cellular WHERE device_id=%s AND interface=%s LIMIT 1",
                (device_id, prefer_iface),
            )
            r = cur.fetchone()
            if r: row_id = r[0]

        if row_id is None:
            cur.execute(
                """
                SELECT id FROM device_cellular
                  WHERE device_id=%s
                  ORDER BY (ip_addr <> 'unassigned') DESC,
                           (status='up') DESC,
                           id DESC
                  LIMIT 1
                """,
                (device_id,),
            )
            r = cur.fetchone()
            if r: row_id = r[0]

        if row_id is not None:
            cur.execute("UPDATE device_cellular SET sim=%s, last_seen=NOW() WHERE id=%s", (sim_text, row_id))
        else:
            cur.execute(
                """
                INSERT INTO device_cellular
                    (device_id, interface, ip_addr, status, protocol, imsi, imei, iccid, apn, sim, modem_firmware, last_seen)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                """,
                (device_id, prefer_iface or "Cellular0/0/0", "unassigned", "down", "", "", "", "", "", sim_text, ""),
            )
        conn.commit()
    finally:
        try: cur.close()
        except: pass
        conn.close()

def delete_device_from_db(device_id):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE id = %s", (device_id,))
    conn.commit(); cursor.close(); conn.close()

def insert_device_to_db(device):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    is_hub = 0
    try:
        if device["ip"] in HUB_PROBE_ALLOWLIST:
            ok, _, _ = detect_dmvpn_hub_over_ssh(device["ip"])
            if ok: is_hub = 1
    except Exception:
        pass

    cur.execute("""
        INSERT INTO devices (name, ip, gateway, apn, email, is_hub, hostname, ios_version, modem_firmware)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (device["name"], device["ip"], device["gateway"], device["apn"],
          device["email"], is_hub,
          device.get("hostname") or None, device.get("ios_version") or None, device.get("modem_firmware") or None))
    conn.commit()
    device_id = cur.lastrowid
    cur.close(); conn.close()

    try:
        replace_device_cellular(device_id, device.get("cellular_details", []))
    except Exception as e:
        print(f"⚠️ saving device_cellular failed: {e}")

# ---------- Cisco/SSH ops ----------
def detect_dmvpn_hub_over_ssh(ip: str, timeout: int = 12):
    # If SSH detection is disabled, never attempt it.
    if not ALLOW_SSH_HUB_DETECT:
        return (False, "Hub detection disabled (no SSH permitted)", {"hub_cfg": False, "tunnel_names": [], "peer_count": 0})
    
    # NEW: respect allow-list
    if ip not in HUB_PROBE_ALLOWLIST:
        return (False, "Hub detection blocked (not in allow-list)", {"hub_cfg": False, "tunnel_names": [], "peer_count": 0})

    username, password = get_ssh_credentials()
    if not username or not password:
        print(f"[HUB-DETECT] {ip} ERROR: no SSH creds")
        return (False, "No SSH credentials", {})

    if not is_device_online(ip):
        print(f"[HUB-DETECT] {ip} ERROR: SSH port unreachable")
        return (False, "SSH port unreachable", {})

    facts = {"hub_cfg": False, "tunnel_names": [], "peer_count": 0}

    def run(cmd: str) -> str:
        try:
            return run_cmd_fresh(ip, username, password, cmd, timeout=timeout)
        except Exception as e:
            print(f"[HUB-DETECT] CMD ERROR for '{cmd}': {e}")
            return ""

    # 1) Look for hub-style config on Tunnel interfaces
    tun_cfg = run("show running-config | section ^interface Tunnel")
    if not tun_cfg.strip():
        tun_cfg = run("show running-config | begin ^interface Tunnel")

    sections = re.split(r"(?m)^interface\s+", tun_cfg)
    hub_tunnels = []
    for sec in sections:
        sec = sec.strip()
        if not sec:
            continue
        m_name = re.match(r"(Tunnel\S+)", sec)
        name = m_name.group(1) if m_name else "Tunnel?"
        has_mgre     = re.search(r"(?m)^\s*tunnel mode gre multipoint\b", sec) is not None
        has_nhs      = re.search(r"(?m)^\s*ip nhrp nhs\b", sec) is not None
        has_redirect = re.search(r"(?m)^\s*ip nhrp redirect\b", sec) is not None
        if has_mgre and (not has_nhs or has_redirect):
            hub_tunnels.append(name)

    facts["hub_cfg"] = len(hub_tunnels) > 0
    facts["tunnel_names"] = hub_tunnels
    if facts["hub_cfg"]:
        return (True, f"DMVPN hub config on {', '.join(hub_tunnels)}", facts)

    # 2) Runtime fingerprints (some platforms lack 'show dmvpn'; 'show ip nhrp' still helps)
    dmvpn_out = run("show dmvpn")
    nhrp_out  = run("show ip nhrp")

    peer_count = 0
    if dmvpn_out:
        peer_count += len(re.findall(r"(?i)\bPeer|Registered|Up|NHRP|NBMA\b", dmvpn_out))
    if nhrp_out:
        peer_count += len(re.findall(r"(?i)\bpeer\b|\bVia:\b|\bRegistrations\b", nhrp_out))
    facts["peer_count"] = peer_count

    if dmvpn_out and re.search(r"(?i)\bType:\s*Hub\b", dmvpn_out):
        return (True, "DMVPN hub (runtime)", facts)

    return (False, "No DMVPN hub fingerprints found", facts)

import re, time, paramiko
from typing import Tuple, Optional

# --- helpers --------------------------------------------------------------

def _open_shell(ssh: paramiko.SSHClient, *, timeout: int) -> paramiko.Channel:
    t = ssh.get_transport()
    if not t or not t.is_active():
        raise RuntimeError("SSH transport not active")
    ch = t.open_session(timeout=timeout)
    ch.get_pty(term="vt100", width=200, height=50)
    ch.invoke_shell()
    ch.settimeout(timeout)
    return ch

def _drain(chan: paramiko.Channel) -> bytes:
    buf = bytearray()
    try:
        while chan.recv_ready():
            buf.extend(chan.recv(65535))
    except Exception:
        pass
    return bytes(buf)

def _read_until_prompt(chan: paramiko.Channel, *, timeout: int) -> str:
    """
    Read from the interactive shell until we see a Cisco-like prompt on a line
    by itself (…..# or …..> with no spaces). Returns decoded text.
    """
    buf = bytearray()
    last_rx = time.time()
    while True:
        if chan.recv_ready():
            chunk = chan.recv(65535)
            if not chunk:
                break
            buf.extend(chunk)
            last_rx = time.time()

            tail = bytes(buf[-1024:])
            # prompt is typically "ALLS102RTR01#" or "...>"
            lines = tail.splitlines()[-3:]
            for line in lines:
                s = line.strip()
                if s and (s.endswith(b'#') or s.endswith(b'>')) and (b' ' not in s):
                    return buf.decode("utf-8", errors="ignore")
        else:
            if time.time() - last_rx > timeout:
                return buf.decode("utf-8", errors="ignore")
            time.sleep(0.05)

def _send(chan: paramiko.Channel, cmd: str):
    chan.send(cmd.rstrip() + "\n")

_IFACE_SHORT = {
    "GigabitEthernet": "G",
    "FastEthernet": "F",
    "TenGigabitEthernet": "Te",
    "HundredGigE": "Hu",
    "Cellular": "Cell",
    "Serial": "S",
    "Vlan": "Vl",
}

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def _shorten_iface(name: str) -> str:
    if not name:
        return name
    for long, short in _IFACE_SHORT.items():
        if name.startswith(long):
            return name.replace(long, short, 1)
    return name

def _iface_from_ip_over_shell(chan, ip: str, timeout: int = 8) -> str | None:
    """Map IP -> interface using a single shell session."""
    _send(chan, "show ip interface brief")
    out = _read_until_prompt(chan, timeout=timeout)
    # Typical line: "GigabitEthernet0/0   192.168.0.1   YES ... up   up"
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == ip:
            return parts[0]
    return None

def _resolve_tunnel_underlay_iface_over_shell(chan, tunnel_if: str, timeout: int = 8) -> str | None:
    """
    For TunnelX, try to find the 'tunnel source' and map it to a physical interface.
    Works for:
      tunnel source <interface>
      tunnel source <ip-address>
    Uses the same shell channel.
    """
    # Prefer running-config view (most consistent across IOS variants)
    _send(chan, f"show running-config interface {tunnel_if}")
    cfg = _read_until_prompt(chan, timeout=timeout)
    m = re.search(r"(?im)^\s*tunnel\s+source\s+(\S+)", cfg)
    src = m.group(1) if m else None

    if not src:
        # Fallback to operational display
        _send(chan, f"show interface {tunnel_if}")
        out2 = _read_until_prompt(chan, timeout=timeout)
        m2 = re.search(r"(?i)tunnel\s+source\s+(\S+)", out2)
        src = m2.group(1) if m2 else None

    if not src:
        return None

    if _IP_RE.match(src):
        # Source is an IP -> find which interface owns it
        return _iface_from_ip_over_shell(chan, src, timeout=timeout)
    else:
        # Source is already an interface name
        return src

def _parse_default_route(route_text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (gw_ip, outgoing_interface). Handles:
    - 'Gateway of last resort is A.B.C.D to network 0.0.0.0'
    - 'S* 0.0.0.0/0 [1/0] via A.B.C.D, Vlan1'
    - 'S* 0.0.0.0/0 is directly connected, Cellular0/0/0'
    - '0.0.0.0/0 is directly connected, Cellular0/0/0'
    """
    text = route_text

    # 1) Explicit "Gateway of last resort is ..." (records the IP only)
    m = re.search(r"Gateway of last resort is\s+((?:\d{1,3}\.){3}\d{1,3})\b", text, re.I)
    gw_ip = m.group(1) if m else None

    # 2) Default route via next-hop, with interface after comma
    m2 = re.search(
        r"^\s*S\*\s+0\.0\.0\.0/0.*?\bvia\s+((?:\d{1,3}\.){3}\d{1,3})\s*,\s*([A-Za-z0-9/\.]+)",
        text, re.M
    )
    if m2:
        return (m2.group(1), m2.group(2))

    # 3) Default route directly connected: interface only
    m3 = re.search(
        r"^\s*(?:S\*\s+)?0\.0\.0\.0/0\s+is\s+directly\s+connected,\s*([A-Za-z0-9/\.]+)",
        text, re.M | re.I
    )
    if m3:
        return (gw_ip, m3.group(1))  # gw_ip may be None, interface is known

    # 4) Fallback: try to pull an interface after "directly connected,"
    m4 = re.search(r"directly connected,\s*([A-Za-z0-9/\.]+)", text)
    if m4 and gw_ip:
        return (gw_ip, m4.group(1))

    # 5) Nothing conclusive
    return (gw_ip, None)

def _infer_iface_for_nexthop_from_route(route_text: str, gw_ip: str) -> str | None:
    """
    From a 'show ip route' dump, figure out which *directly connected* interface
    would be used to reach gw_ip. Prefer the most-specific connected prefix.
    """
    if not gw_ip:
        return None
    try:
        gw = ipaddress.ip_address(gw_ip)
    except Exception:
        return None

    best: tuple[int, str] | None = None  # (prefixlen, iface)

    for raw in route_text.splitlines():
        line = raw.strip()
        # Match connected/local lines, e.g.:
        #   C 192.168.1.0/24 is directly connected, GigabitEthernet0/0
        #   L 192.168.1.151/32 is directly connected, GigabitEthernet0/0
        m = re.match(r'^[CL]\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d+).*?directly connected,\s+(\S+)', line)
        if not m:
            continue
        net, plen_s, iface = m.group(1), m.group(2), m.group(3)
        # ignore loopbacks as candidates
        if iface.lower().startswith("loopback"):
            continue
        try:
            n = ipaddress.ip_network(f"{net}/{int(plen_s)}", strict=False)
        except Exception:
            continue
        if gw in n:
            cand = (int(plen_s), iface)
            if (best is None) or (cand[0] > best[0]):
                best = cand

    if best:
        return best[1]

    # Secondary pattern: some IOS show the iface on the default line:
    # S* 0.0.0.0/0 [1/0] via 192.168.1.1, 00:01:23, GigabitEthernet0/0
    m2 = re.search(
        rf'S\*\s+0\.0\.0\.0/0.*?via\s+{re.escape(gw_ip)}(?:,\s*\S+)*,\s*(\S+)',
        route_text
    )
    if m2:
        iface = m2.group(1)
        if not iface.lower().startswith("loopback"):
            return iface

    return None

# --- main API -------------------------------------------------------------
def detect_default_gateway(ip: str, username: str, password: str, *, vrf: str | None = None, timeout: int = 20):
    """
    ONE-PTY shell; returns (gw_ip, resolved_iface).
    Display text can be built by the caller as: f"{gw_ip} ({resolved_iface})".
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password,
                look_for_keys=False, allow_agent=False, timeout=timeout)
    try:
        try:
            ssh.get_transport().set_keepalive(15)
        except Exception:
            pass

        chan = _open_shell(ssh, timeout=timeout)
        time.sleep(0.2); _drain(chan)

        _send(chan, "terminal length 0")
        _read_until_prompt(chan, timeout=timeout)

        route_cmd = f"show ip route{' vrf ' + vrf if vrf else ''}"
        _send(chan, route_cmd)
        route_text = _read_until_prompt(chan, timeout=timeout)

        gw_ip, iface = _parse_default_route(route_text)

        # Fallback: default route only in config
        if not gw_ip and not iface:
            cfg_cmd = (f"show running-config | include ^ip route vrf {vrf} 0.0.0.0 0.0.0.0"
                       if vrf else "show running-config | include ^ip route 0.0.0.0 0.0.0.0")
            _send(chan, cfg_cmd)
            cfg_text = _read_until_prompt(chan, timeout=timeout)
            m_cfg = re.search(r"ip route (?:vrf \S+\s+)?0\.0\.0\.0 0\.0\.0\.0\s+((?:\d{1,3}\.){3}\d{1,3})", cfg_text)
            if m_cfg:
                gw_ip = m_cfg.group(1)

        # >>> NEW: infer real egress iface for the next-hop if we have gw_ip
        resolved_iface = iface
        if gw_ip:
            egress = _infer_iface_for_nexthop_from_route(route_text, gw_ip)
            if egress:
                resolved_iface = egress

        # Only if we *still* have a Tunnel (or no iface at all), try underlay resolution.
        if resolved_iface and resolved_iface.lower().startswith("tunnel"):
            underlay = _resolve_tunnel_underlay_iface_over_shell(chan, resolved_iface, timeout=timeout)
            if underlay and not underlay.lower().startswith("loopback"):
                resolved_iface = underlay

        # Shorten for UI
        if resolved_iface:
            name = resolved_iface.strip()
            if not name.lower().startswith("fastethernet"):
                resolved_iface = _shorten_iface(name)
            else:
                resolved_iface = name

        try:
            chan.close()
        except Exception:
            pass

        return gw_ip, resolved_iface

    finally:
        try:
            ssh.close()
        except Exception:
            pass

def list_cellular_interfaces(ip: str, timeout: int = 8):
    if not is_device_online(ip):
        return []

    username, password = get_ssh_credentials()
    if not username or not password:
        return []

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=username, password=password,
                    look_for_keys=False, allow_agent=False,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)
        _, stdout, _ = ssh.exec_command("show ip interface brief")
        out = stdout.read().decode(errors="ignore")
    except Exception:
        return []
    finally:
        try: ssh.close()
        except: pass

    results = []
    for raw in out.splitlines():
        if not re.match(r"^\s*Cellular[\d/]+", raw, re.I):
            continue
        cols = re.split(r"\s+", raw.strip())
        name = cols[0] if len(cols) > 0 else ""
        ipaddr = cols[1] if len(cols) > 1 else ""
        status = " ".join(cols[4:-1]) if len(cols) >= 6 else (cols[4] if len(cols) > 4 else "")
        protocol = cols[-1] if cols else ""
        results.append({"name": name, "ip": ipaddr, "status": status, "protocol": protocol})

    print("[DBG] show ip int brief parsed:", results)
    return results

def parse_ids_from_cellular_text(text: str):
    """
    Parse one slot's text. Supports multiple IOS XE phrasings.
    Returns (imsi, imei, iccid).
    """
    imsi = imei = iccid = ""

    # IMSI: allow "IMSI =" or "International Mobile Subscriber Identity (IMSI) ="
    m = re.search(
        r"(?im)^\s*(?:International\s+Mobile\s+Subscriber\s+Identity\s*\(IMSI\)\s*|(?:SIM\s*\d+\s*)?IMSI)\s*[:=]\s*([0-9]{6,20})\b",
        text
    )
    if m:
        imsi = m.group(1)

    # IMEI: current pattern already handles long/short forms with (IMEI)
    m = re.search(
        r"(?im)^\s*(?:International\s+Mobile\s+Equipment\s+Identity\s*\(IMEI\)\s*|IMEI)\s*[:=]\s*([0-9]{8,20})\b",
        text
    )
    if m:
        imei = m.group(1)

    # ICCID: allow "Integrated Circuit Card ID (ICCID) =" or "ICCID (SIM x) ="
    m = re.search(
        r"(?im)^\s*(?:Integrated\s+Circuit\s+Card\s+ID(?:\s*\(ICCID\))?|ICCID(?:\s*\(\s*SIM\s*\d+\s*\))?)\s*[:=]\s*([0-9A-Fa-f]{10,30})\b",
        text
    )
    if m:
        iccid = m.group(1)

    return imsi, imei, iccid

def fetch_cellular_ids_for_interface(ip: str, if_name: str, timeout: int = 8):
    m = re.search(r"Cellular(\d+/\d+/\d+)", if_name, re.I)
    if not m:
        raise RuntimeError(f"Cannot parse slot from {if_name}")
    slot = m.group(1)

    username, password = get_ssh_credentials()
    if not username or not password:
        raise RuntimeError("SSH credentials not set.")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=username, password=password,
                    look_for_keys=False, allow_agent=False,
                    timeout=timeout, banner_timeout=timeout, auth_timeout=timeout)

        # Prefer commands that scope to *this* slot only.
        candidates = [
            f"show cellular {slot} hardware",
            f"show cellular {slot} security sim",
            f"show cellular {slot} sim info",
            f"show cellular {slot} sim detail",
            f"show cellular {slot} profile",
            f"show cellular {slot} lte profile",
            f"show cellular {slot} all",  # last resort
        ]


        combined = ""
        for cmd in candidates:
            try:
                _stdin, stdout, _stderr = ssh.exec_command(cmd, timeout=timeout)
                out = stdout.read().decode(errors="ignore")
                combined += f"\n--- {cmd} ---\n{out}"
            except Exception:
                # keep going; some commands won’t exist on some platforms
                pass

    finally:
        try: ssh.close()
        except: pass

    # Parse only from the collected, slot-scoped text
    imsi, imei, iccid = parse_ids_from_cellular_text(combined)
    msisdn = _parse_msisdn(combined)
    return {"interface": if_name, "imsi": imsi, "imei": imei, "iccid": iccid, "sim": msisdn}


def fetch_all_cellular_details(ip: str, timeout: int = 8):
    infos = list_cellular_interfaces(ip, timeout=timeout)
    details = []
    for i in infos:
        ids = {"interface": i["name"], "imsi": "", "imei": "", "iccid": "", "sim": ""}
        try:
            fetched = fetch_cellular_ids_for_interface(ip, i["name"], timeout=timeout)
            # Only set if non-empty (keeps per-slot independence)
            if fetched.get("imsi"):  ids["imsi"]  = fetched["imsi"]
            if fetched.get("imei"):  ids["imei"]  = fetched["imei"]
            if fetched.get("iccid"): ids["iccid"] = fetched["iccid"]
            if fetched.get("sim"):   ids["sim"]   = fetched["sim"]
        except Exception as e:
            ids["iccid"] = f"ERROR: {e}"

        ids.update({
            "ip": i.get("ip", ""),
            "status": i.get("status", ""),
            "protocol": i.get("protocol", ""),
        })
        details.append(ids)
    return details

def extract_sms_content(sms_text: str) -> str:
    lines = sms_text.strip().splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("SIZE:"):
            if i + 1 < len(lines):
                return lines[i + 1].strip().strip('"')
    return ""

def _normalize_cellular_iface(s: str) -> str:
    """
    Accepts: 'Cellular0/1/0', 'cellular 0/1/0', '0/1/0', etc.
    Returns: 'cellular 0/1/0'
    """
    s = (s or "").strip()
    # pull the slot/port/controller (e.g. 0/1/0)
    m = re.search(r'(\d+/\d+/\d+)', s)
    if m:
        return f"cellular {m.group(1)}"
    # safe default
    return "cellular 0/1/0"


def _alive(t):
    try:
        return bool(t and t.is_active())
    except Exception:
        return False
    
import re, time, paramiko

_PROMPT_LINE_RE = re.compile(rb'^[^\r\n]*[>#]\s*$', re.M)
_TERM_LEN_RE    = re.compile(r'(?:\bterminal\b.*\blength\b|^term\s+len.*$|length\s*=\s*0)', re.I)

def _strip_term_len_noise(s: str) -> str:
    if not s: return s
    return '\n'.join(ln for ln in s.splitlines() if not _TERM_LEN_RE.search(ln))

def _capture_prompt_line(chan, timeout: float = 2.5) -> bytes:
    """Ask device to print prompt once; return that exact line (bytes, no CRLF)."""
    deadline = time.time() + timeout
    buf = bytearray()
    chan.send('\n')
    while time.time() < deadline:
        if chan.recv_ready():
            chunk = chan.recv(65535)
            if not chunk:
                break
            buf.extend(chunk)
            tail = bytes(buf[-2048:])
            m = _PROMPT_LINE_RE.search(tail)
            if m:
                # return the last prompt-like line
                lines = tail.splitlines()
                for i in range(len(lines) - 1, -1, -1):
                    if _PROMPT_LINE_RE.match(lines[i]):
                        return lines[i].rstrip()
        else:
            time.sleep(0.03)
    return b'#'

def run_one_cmd_standalone(transport: paramiko.Transport, cmd: str, timeout: int = 30) -> str:
    """
    Open a fresh PTY shell for `cmd`, set 'terminal length 0', read until prompt reappears,
    close shell, and return cleaned output.
    """
    if not transport or not transport.is_active():
        raise RuntimeError("SSH transport not active")

    chan = transport.open_session(timeout=timeout)
    try:
        chan.get_pty(term='vt100', width=200, height=50)
        chan.invoke_shell()
        chan.settimeout(timeout)

        def drain_all():
            buf = bytearray()
            while chan.recv_ready():
                chunk = chan.recv(65535)
                if not chunk:
                    break
                buf.extend(chunk)
            return bytes(buf)

        # settle
        time.sleep(0.12)
        drain_all()

        # capture exact prompt once
        prompt_line = _capture_prompt_line(chan) or b'#'

        # try enable if in exec mode
        if prompt_line.endswith(b'>'):
            chan.send('enable\n'); time.sleep(0.15)
            tmp = drain_all()
            if b'assword' in tmp or b'assword' in tmp.lower():
                # cancel enable
                chan.send('\n'); time.sleep(0.15); drain_all()
            prompt_line = _capture_prompt_line(chan) or prompt_line

        # disable paging (and flush the confirmation)
        chan.send('terminal length 0\n'); time.sleep(0.15); drain_all()

        # send the command
        chan.send(cmd.rstrip() + '\n')
        time.sleep(0.05)  # small nudge so device starts writing

        buf = bytearray()
        last_rx = time.time()
        saw_body = False
        more_pat = re.compile(br'--More--|\(q\)uit', re.I)

        while True:
            if chan.recv_ready():
                chunk = chan.recv(65535)
                if not chunk:
                    break
                buf.extend(chunk)
                last_rx = time.time()

                tail = bytes(buf[-2048:])

                if more_pat.search(tail):
                    chan.send(' ')
                    continue

                # treat as body once we see the echo or typical structured lines
                if (cmd.encode() in tail) or (b':' in tail) or (b'\n' in tail):
                    if not _TERM_LEN_RE.search(tail.decode('utf-8', 'ignore')):
                        saw_body = True

                # stop only after body and *exact* prompt line reappear
                if saw_body:
                    # examine the last line
                    last_nl = tail.rfind(b'\n')
                    last_line = tail[last_nl+1:] if last_nl != -1 else tail
                    if last_line.rstrip().endswith(prompt_line):
                        break
            else:
                if time.time() - last_rx > timeout:
                    break
                time.sleep(0.04)

        raw = buf.decode('utf-8', 'ignore')

        # remove echoed command (first occurrence only)
        idx = raw.find(cmd)
        if idx != -1:
            nl = raw.find('\n', idx)
            if nl != -1:
                raw = raw[nl+1:]

        # drop trailing prompt line (exact)
        raw = re.sub(rf"\r?\n{re.escape(prompt_line.decode('utf-8','ignore'))}\s*$", "", raw)

        # clean pager/ANSI/term-len noise
        raw = re.sub(r'--More--|\(q\)uit', '', raw, flags=re.I)
        raw = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw)
        raw = _strip_term_len_noise(raw)

        return raw.strip()
    finally:
        try: chan.close()
        except Exception: pass
    
def run_cmds_resilient_over_ssh(ip: str, username: str, password: str,
                                cmds: list[str], timeout: int = 30) -> dict[str, str]:
    """
    Open an SSH connection, run each cmd in its own fresh PTY shell.
    If the transport dies between commands, reconnect once and continue.
    """
    out: dict[str, str] = {}
    ssh = None

    def _connect(_tries=2):
        return ssh_connect_resilient(ip, username, password, tries=_tries)

    try:
        ssh = _connect(_tries=2)
        for c in cmds:
            try:
                t = ssh.get_transport()
                out[c] = run_one_cmd_standalone(t, c, timeout=timeout)
            except Exception as e:
                # reconnect once, then retry this command
                try:
                    if ssh:
                        ssh.close()
                except:
                    pass
                ssh = _connect(_tries=1)
                t = ssh.get_transport()
                try:
                    out[c] = run_one_cmd_standalone(t, c, timeout=timeout)
                except Exception:
                    # give up on this cmd but keep going for the rest
                    out[c] = ""
    finally:
        try:
            if ssh:
                ssh.close()
        except:
            pass

    return out

def fetch_last_sms(ip):
    try:
        if not list_cellular_interfaces(ip):
            return "No Cellular"
        username, password = get_ssh_credentials()
        if not (username and password):
            return "Error: No SSH creds"

        ssh = ssh_connect_resilient(ip, username, password, tries=2)
        try:
            t = ssh.get_transport()
            sms_iface = choose_sms_iface(ip)  # e.g., 'cellular 0/1/0'
            iface_cmd = _normalize_cellular_iface(sms_iface)  # same as before

            # First pass: list all IDs (try both LTE & legacy forms)
            list_cmds = [
                f"{iface_cmd} lte sms view all",
            ]
            # results = run_cmds_resilient_over_ssh(None, t, list_cmds, timeout=25)
            results = run_cmds_resilient_over_ssh(ip, username, password, list_cmds, timeout=25)
            sms_list_output = next((v for v in (results.get(c, "") for c in list_cmds) if v), "")

            if not sms_list_output:
                # DEBUG: dump once so we can see what came back
                with open("last_sms_debug.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n[{ip}] Empty list output at {time.strftime('%F %T')}\n")
                    for c in list_cmds:
                        f.write(f"--- {c} ---\n{results.get(c,'')}\n")
                return "No SMS"

            ids = re.findall(r"SMS ID:\s*(\d+)", sms_list_output)
            if not ids:
                return "No SMS"
            last = max(map(int, ids))

            # Second pass: view the last one (again try forms)
            view_cmds = [
                f"{iface_cmd} lte sms view {last}",
            ]
            
            if not _alive(t):
                t = ssh.get_transport()

            # res2 = run_cmds_resilient_over_ssh(None, t, view_cmds, timeout=25)
            res2 = run_cmds_resilient_over_ssh(ip, username, password, view_cmds, timeout=25)
            sms_view_output = next((v for v in (res2.get(c, "") for c in view_cmds) if v), "")

            if not sms_view_output:
                with open("last_sms_debug.txt", "a", encoding="utf-8") as f:
                    f.write(f"\n[{ip}] Empty view output for ID {last} at {time.strftime('%F %T')}\n")
                    for c in view_cmds:
                        f.write(f"--- {c} ---\n{res2.get(c,'')}\n")
                return "No SMS"

            return sms_view_output.strip()
        finally:
            try:
                ssh.close()
            except Exception:
                pass
    except Exception as e:
        return f"Error: {e}"
    
def fetch_sms_details(router_ip, sms_index):
    ssh = paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username, password = get_ssh_credentials()
    ssh.connect(router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
    chosen_iface = choose_sms_iface(router_ip)   # ← NEW
    command = f"{chosen_iface} lte sms view {sms_index}"     # ← was hard-coded 0/0/0
    _, stdout, _ = ssh.exec_command(command)
    sms_output = stdout.read().decode()
    ssh.close()
    print(f"📩 Raw SMS output:\n{sms_output}")

    sms_id = re.search(r"SMS ID: (\d+)", sms_output)
    sms_time = re.search(r"TIME: ([\d-]+ [\d:]+)", sms_output)
    sms_from = re.search(r"FROM: (\d+)", sms_output)
    sms_size = re.search(r"SIZE: (\d+)", sms_output)
    sms_content_match = re.search(r"SIZE: \d+\s*(.+)", sms_output, re.DOTALL)

    if not all([sms_id, sms_time, sms_from, sms_size, sms_content_match]):
        print("⚠️ Failed to extract SMS fields.")
        return {"ID": "Unknown", "Time": "Unknown", "From": "Unknown", "Size": "Unknown",
                "Content": "Failed to parse SMS content"}

    return {
        "ID": sms_id.group(1),
        "Time": sms_time.group(1),
        "From": sms_from.group(1),
        "Size": sms_size.group(1),
        "Content": sms_content_match.group(1).strip(),
    }

# ---------- Email notification settings ----------
def safe_set_text(widget, value):
    text_value = str(value) if value is not None else ""
    if hasattr(widget, "setPlainText"):
        widget.setPlainText(text_value)
    elif hasattr(widget, "setText"):
        widget.setText(text_value)
    else:
        raise TypeError(f"Widget {type(widget).__name__} is not supported")

def safe_get_text(widget):
    if hasattr(widget, "toPlainText"):
        return widget.toPlainText().strip()
    elif hasattr(widget, "text"):
        return widget.text().strip()
    else:
        raise TypeError(f"Widget {type(widget).__name__} is not supported")

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
            cursor.close(); conn.close()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", str(e))

    def save_setting(self):
        subject = safe_get_text(self.subjectEdit)
        email   = safe_get_text(self.emailEdit)
        content = safe_get_text(self.contentEdit)
        if not subject or not email or not content:
            QtWidgets.QMessageBox.warning(self, "Missing Fields", "subject, email and content are required.")
            return
        try:
            db_config = get_db_config()
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM email_notification")
            cursor.execute("INSERT INTO email_notification (subject, email, content) VALUES (%s, %s, %s)",
                           (subject, email, content))
            conn.commit(); cursor.close(); conn.close()
            QtWidgets.QMessageBox.information(self, "Saved", "Email Notification Setting updated.")
            self.accept()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", str(e))

# ---------- Email profiles (kept) ----------
def get_email_profiles():
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, profile_name, smtp_server, smtp_port, sender_email, sender_password, security, is_default
        FROM email_settings ORDER BY is_default DESC, profile_name ASC
    """)
    rows = cur.fetchall(); cur.close(); conn.close()
    return rows

def get_default_email_profile():
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, profile_name, smtp_server, smtp_port, sender_email, sender_password, security, is_default
        FROM email_settings ORDER BY is_default DESC, profile_name ASC LIMIT 1
    """)
    row = cur.fetchone(); cur.close(); conn.close()
    return row

def upsert_email_profile(profile):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
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
    conn.commit(); cur.close(); conn.close()

def delete_email_profile(profile_id):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cur = conn.cursor()
    cur.execute("DELETE FROM email_settings WHERE id=%s", (int(profile_id),))
    conn.commit(); cur.close(); conn.close()

# ---------- Cisco EEM ----------
def configure_sms_applet_on_cisco(router_ip, username, password):
    eem_script = f"""
        configure terminal
        no event manager applet SMS_Extract
        event manager applet SMS_Extract
        event syslog pattern "Cellular[0-9]/[0-9]/[0-9]: New SMS received on index ([0-9]+)"
        action 1.0 cli command "enable"
        ! Extract interface slot and index from the syslog line
        action 2.0 regexp "Cellular([0-9]/[0-9]/[0-9]): New SMS received on index ([0-9]+)" "$_syslog_msg" match ifslot sms_index
        action 3.0 cli command "cellular $ifslot lte sms view $sms_index"
        action 4.0 syslog msg "SMS Extracted -> ID: $sms_index"
        !
        logging host {get_ip_address()}
        logging trap informational
        end
        write memory
        """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        shell = ssh.invoke_shell(); time.sleep(1); shell.recv(1000)
        for line in eem_script.strip().split("\n"):
            shell.send(line.rstrip() + "\n"); time.sleep(0.3)
        _ = shell.recv(10000).decode(errors="ignore")
        ssh.close()
        print(f"EEM applet configured on {router_ip}")
    except Exception as e:
        print(f"Failed to configure EEM on {router_ip}: {e}")

# ---------- SMS DB ingest ----------
def get_all_sms(ip):
    username, password = get_ssh_credentials()
    if not username or not password or not is_device_online(ip) or not list_cellular_interfaces(ip):
        return ""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password,
                look_for_keys=False, allow_agent=False,
                timeout=3, banner_timeout=3, auth_timeout=3)
    sms_iface = choose_sms_iface(ip)
    _, stdout, _ = ssh.exec_command(f"{sms_iface} lte sms view all")
    out = stdout.read().decode(); ssh.close()
    return out

def parse_sms(raw_output):
    sms_blocks = raw_output.strip().split("--------------------------------------------------------------------------------")
    sms_list = []
    for block in sms_blocks:
        if not block.strip(): continue
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
                    smsFrom = "0" + raw[2:] if raw.startswith("61") else raw
                elif is_hex_string(raw):
                    smsFrom = gsm7_unpack(raw)
                else:
                    smsFrom = raw
                sms["From"] = smsFrom
                sms["CiscoFrom"] = raw
            elif line.startswith("SIZE:"):
                sms["Size"] = int(line.replace("SIZE:", "").strip())
            else:
                sms["Message"] = sms.get("Message", "") + " " + line.strip()
        sms_list.append(sms)
    return sms_list

def get_new_sms_by_time(ip, last_time):
    raw = get_all_sms(ip)
    all_sms = parse_sms(raw)
    return [sms for sms in all_sms if sms["Time"] > last_time]

def save_sms_to_db(sms_list, device):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    sql = """
    INSERT IGNORE INTO sms_logs (dates, sms_from, cisco_from, size, message, devices_id)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    for sms in sms_list:
        cursor.execute(sql, (sms["Time"], sms["From"], sms["CiscoFrom"], sms["Size"],
                             sms["Message"], device["id"]))
    conn.commit(); cursor.close()

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM email_notification LIMIT 1")
    row = cursor.fetchone()
    if row:
        subject, email, content = row[1], row[2], row[3]
    else:
        subject = email = content = None
    cursor.close(); conn.close()

    db_config_ti = get_db_config_ti()
    if not db_config_ti: return
    conn = mysql.connector.connect(**db_config_ti)
    now = datetime.now()
    cursor = conn.cursor()
    sql = """
    INSERT INTO logbulkmail(dates, times, sendto, mailsubject, mailcontent, mailstatus,
                            mailtype, cc, spoofas, spoofname, attachment) 
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    for sms in sms_list:
        mailcontent = (f"{content}<br />---------<br />From: {sms['From']}<br />"
                       f"Received: {sms['Time']}<br />SIM Detail: {device['name']} - {device['sim']}<br />"
                       f"Message: {sms['Message']}")
        emailReceive = sms["From"] + "@alliedsms.com.au"
        cursor.execute(sql, (now.date(), now.strftime("%I:%M:%S %p"), email,
                             subject + " - " +  emailReceive, mailcontent,
                             "Queue In Database", "Email", 1, emailReceive, emailReceive, 0))
    conn.commit(); cursor.close(); conn.close()

def fetch_from_all_devices(devices):
    def _as_dt(v):
        if v is None:
            return datetime.strptime("2000-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
        if isinstance(v, datetime):
            return v
        try:
            return datetime.strptime(str(v), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return datetime.strptime("2000-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")

    db_config = get_db_config()
    if not db_config:
        print("❌ No DB config; fetch_from_all_devices aborted.")
        return []

    for device in devices:
        ip = device.get("ip"); dev_id = device.get("id")
        if not ip or not is_device_online(ip):
            continue
        if not device.get("has_cellular", False):
            continue

        last_time = datetime.strptime("2000-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
        try:
            conn = mysql.connector.connect(**db_config)
            cur = conn.cursor()
            cur.execute("SELECT MAX(dates) FROM sms_logs WHERE devices_id=%s", (dev_id,))
            row = cur.fetchone(); cur.close(); conn.close()
            last_time = _as_dt(row[0] if row else None)
        except Exception as e:
            print(f"⚠️ Failed reading last_time for device {dev_id} ({ip}): {e}")
        try:
            new_sms = get_new_sms_by_time(ip, last_time)
        except Exception as e:
            print(f"⚠️ get_new_sms_by_time failed for {ip}: {e}")
            new_sms = []
        if new_sms:
            try:
                save_sms_to_db(new_sms, device)
                print(f"✅ {len(new_sms)} new SMS from {ip} saved")
            except Exception as e:
                print(f"❌ Failed saving SMS for {ip}: {e}")

    try:
        conn = mysql.connector.connect(**db_config)
        cur = conn.cursor()
        cur.execute("""
            SELECT d.name, s.dates, s.sms_from, s.message
            FROM devices d
            INNER JOIN sms_logs s ON s.devices_id = d.id
            ORDER BY s.dates DESC, s.id DESC
        """)
        sms_list = cur.fetchall(); cur.close(); conn.close()
        return sms_list
    except Exception as e:
        print(f"❌ Failed to build SMS list for UI: {e}")
        return []

# ---------- Credentials dialogs ----------
class SSHCredentialsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        uic.loadUi(resource_path("ssh_credentials_dialog.ui"), self)
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
            cursor.close(); conn.close()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", str(e))

    def save_credentials(self):
        username = self.usernameLineEdit.text().strip()
        password = self.passwordLineEdit.text().strip()
        if not username or not password:
            QtWidgets.QMessageBox.warning(self, "Missing Fields", "Username and password are required.")
            return
        encrypted = encrypt_password(password)
        try:
            db_config = get_db_config()
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM user_ssh")
            cursor.execute("INSERT INTO user_ssh (username, password) VALUES (%s, %s)", (username, encrypted))
            conn.commit(); cursor.close(); conn.close()
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
            ); conn.close()
            conn = mysql.connector.connect(
                host=self.hostLineEdit.text(),
                port=self.portSpinBox.value(),
                user=self.userLineEdit.text(),
                password=self.passwordLineEdit.text(),
                database=self.databaseTILineEdit.text()
            ); conn.close()
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
        row = cursor.fetchone(); cursor.close(); conn.close()
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
        conn.commit(); cursor.close(); conn.close()
        self.accept()

# ---------- Signals ----------
class WorkerSignals(QObject):
    deviceAdded = pyqtSignal(list)
    smsLogsFetched = pyqtSignal(str, list)
    refreshCompleted = pyqtSignal(list)
    smsLogsFetched = QtCore.pyqtSignal(str, list)

class SMSUpdateSignal(QObject):
    smsFetched = pyqtSignal(int, str)

class IPItem(QtWidgets.QTableWidgetItem):
    def __lt__(self, other):
        def ip_key(s):
            try:
                a, b, c, d = (int(x) for x in s.split("."))
                return (a, b, c, d)
            except Exception:
                return (999, 999, 999, 999)
        return ip_key(self.text()) < ip_key(other.text())

class CellularPickerDialog(QtWidgets.QDialog):
    """
    Lets the user pick which Cellular interface to use when >1 are found.
    Expects a list of dicts: {"interface","ip","imsi","imei","iccid"}.
    """
    def __init__(self, details, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Select Cellular Interface")
        self.setModal(True)
        self._details = details
        v = QVBoxLayout(self)

        self.table = QtWidgets.QTableWidget(len(details), 5, self)
        self.table.setHorizontalHeaderLabels(["Interface", "IP", "IMSI", "IMEI", "ICCID"])
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)

        for r, d in enumerate(details):
            self.table.setItem(r, 0, QtWidgets.QTableWidgetItem(d.get("interface","")))
            self.table.setItem(r, 1, QtWidgets.QTableWidgetItem(d.get("ip","")))
            self.table.setItem(r, 2, QtWidgets.QTableWidgetItem(d.get("imsi","")))
            self.table.setItem(r, 3, QtWidgets.QTableWidgetItem(d.get("imei","")))
            self.table.setItem(r, 4, QtWidgets.QTableWidgetItem(d.get("iccid","")))
        self.table.resizeColumnsToContents()
        v.addWidget(self.table)

        bb = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)

        # Preselect best row: prefer interface with an IP address
        best = 0
        for idx, d in enumerate(details):
            ip = (d.get("ip") or "").strip().lower()
            if ip and ip != "unassigned":
                best = idx
                break
        self.table.selectRow(best)

    def selected_detail(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        return {
            "interface": self.table.item(row, 0).text() if self.table.item(row, 0) else "",
            "ip":        self.table.item(row, 1).text() if self.table.item(row, 1) else "",
            "imsi":      self.table.item(row, 2).text() if self.table.item(row, 2) else "",
            "imei":      self.table.item(row, 3).text() if self.table.item(row, 3) else "",
            "iccid":     self.table.item(row, 4).text() if self.table.item(row, 4) else "",
        }

# ---------- Device settings dialog ----------
class DetectSignals(QObject):
    apnDetected = pyqtSignal(str)
    gatewayDetected = pyqtSignal(str)
    detectFailed = pyqtSignal(str)
    cellularDetected = pyqtSignal(list)
    prefillDetected = pyqtSignal(list)
    allDetected = pyqtSignal(object, list, object, object)  # gw, details, apn, err

class DeviceSettingsDialog(QtWidgets.QDialog):
    def __init__(self, device=None, parent=None):
        super(DeviceSettingsDialog, self).__init__(parent)
        uic.loadUi(resource_path("device_settings_dialog.ui"), self)

        # at top of DeviceSettingsDialog.__init__
        self._detectAllWatchdog = QtCore.QTimer(self)
        self._detectAllWatchdog.setSingleShot(True)
        self._detectAllWatchdog.timeout.connect(self._detect_all_timed_out)

        # signals
        self.detectSignals = DetectSignals()
        self.detectSignals.apnDetected.connect(self.on_apn_detected)
        self.detectSignals.gatewayDetected.connect(self.on_gateway_detected)
        self.detectSignals.detectFailed.connect(self.on_apn_failed)
        self.detectSignals.cellularDetected.connect(self.on_cellular_detected)
        self.detectSignals.prefillDetected.connect(self._apply_cellular_ids_silent)
        self.detectSignals.allDetected.connect(self._on_all_detected)

        self._prefill_started = False

        # overlay
        self.overlay = QWidget(self)
        self.overlay.setStyleSheet("background: rgba(255, 255, 255, 0.7);")
        self.overlay.hide()
        self.overlay.setGeometry(self.rect())
        self.overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.overlaySpinner = LoadingSpinner(self.overlay)
        self.overlaySpinner.setFixedSize(80, 80)
        self.overlaySpinner.setGeometry(self.overlay.width()//2-40, self.overlay.height()//2-40, 80, 80)

        self.overlay.raise_() 

        self.gatewaySpinner = LoadingSpinner(self)

        layout: QtWidgets.QVBoxLayout = self.layout()
        
        # --- Interface row (dropdown + status dot)
        self.ifaceCombo = QtWidgets.QComboBox()
        self.ifaceStatus = QtWidgets.QLabel("●")
        self.ifaceStatus.setStyleSheet("QLabel { color:#9ca3af; font-size:14px; }")
        iface_row_layout = QHBoxLayout()
        iface_row_layout.addWidget(QtWidgets.QLabel("Interface"))
        iface_row_layout.addWidget(self.ifaceCombo, 1)
        iface_row_layout.addWidget(self.ifaceStatus)

        # Gateway row
        self.detectGatewayButton = QPushButton("Detect")
        getway_row_layout = QHBoxLayout()
        getway_row_layout.addWidget(self.gatewayLineEdit)
        getway_row_layout.addWidget(self.detectGatewayButton)
        getway_row_layout.addWidget(self.gatewaySpinner)

        # APN row
        self.detectApnButton = QPushButton("Detect")
        apn_row_layout = QHBoxLayout()
        apn_row_layout.addWidget(self.apnLineEdit)
        apn_row_layout.addWidget(self.detectApnButton)

        # Detect Cellular row
        self.detectCellButton = QPushButton("Detect Cellular…")
        cell_row_layout = QHBoxLayout()
        cell_row_layout.addStretch(1)
        cell_row_layout.addWidget(self.detectCellButton)

        # --- Interface row (dropdown + status dot)
        self.ifaceCombo = QtWidgets.QComboBox()
        self.ifaceCombo.setObjectName("ifaceCombo")
        self.ifaceStatus = QtWidgets.QLabel("●")
        self.ifaceStatus.setObjectName("ifaceStatus")
        self.ifaceStatus.setStyleSheet("QLabel { color:#9ca3af; font-size:14px; }")  # gray by default
        iface_row_layout = QHBoxLayout()
        iface_row_layout.addWidget(QtWidgets.QLabel("Interface"))
        iface_row_layout.addWidget(self.ifaceCombo, 1)
        iface_row_layout.addWidget(self.ifaceStatus)

        # attach to main layout
        layout: QtWidgets.QVBoxLayout = self.layout()
        layout.insertLayout(2, getway_row_layout)
        layout.insertLayout(3, apn_row_layout)
        layout.insertLayout(4, cell_row_layout)
        layout.insertLayout(5, iface_row_layout)   # now safe

        self._ensure_id_fields(layout)

        # clicks
        self.detectApnButton.clicked.connect(self.handle_detect_apn)
        self.detectGatewayButton.clicked.connect(self.handle_detect_gateway)
        self.detectCellButton.clicked.connect(self.handle_detect_cellular)

        self.device = device or {}
        self.device_id = self.device.get("id")
        if device and device.get("id"):
            saved = get_device_cellular(device["id"])
            # map to the structure used by the combo
            details = []
            for r in saved:
                details.append({
                    "interface": r["interface"],
                    "ip_addr": (r.get("ip_addr") or "").strip(),
                    "ip": (r.get("ip_addr") or "").strip(),     # backward-compatible
                    "status": (r.get("status") or "").strip(),
                    "protocol": (r.get("protocol") or "").strip(),
                    "imsi": (r.get("imsi") or "").strip(),
                    "imei": (r.get("imei") or "").strip(),
                    "iccid": (r.get("iccid") or "").strip(),
                    "apn": (r.get("apn") or "").strip(),
                    "sim": (r.get("sim") or "").strip(),
                })
            if details:
                self._set_interface_list(details, select_best=True)

        if device:
            self.nameLineEdit.setText(device["name"])
            self.ipLineEdit.setText(device["ip"])
            self.gatewayLineEdit.setText(device["gateway"])
            self.hostnameLineEdit.setText(device.get("hostname",""))
            self.iosLineEdit.setText(device.get("ios_version",""))
            self.fwLineEdit.setText(device.get("modem_firmware",""))
            self.simLineEdit.setText(device["sim"])
            self.apnLineEdit.setText(device["apn"])
            self.emailLineEdit.setText(device["email"])
            # button enablement correct
            has_cell = bool(device.get("has_cellular", True))
            self.detectApnButton.setEnabled(has_cell)
            if not has_cell:
                self.detectApnButton.setToolTip("No cellular interface on this router")
            self._user_edited_sim = False
            self.simLineEdit.textEdited.connect(lambda _t: setattr(self, "_user_edited_sim", True))
            # keep a stable copy of what the dialog started with
            self._sim_locked = (self.simLineEdit.text() or (device.get("sim") if isinstance(device, dict) else "") or "").strip()

        self.saveButton.clicked.connect(self.accept)
        self.cancelButton.clicked.connect(self.reject)

        self.ifaceCombo.currentIndexChanged.connect(self._on_iface_changed)
        self._cell_details = []   # holds the list we put in the combo
        self.selected_interface = ""

        self._busy_widgets = []
        self._collect_busy_widgets()
        self.resizeEvent = self._resize_event_forward

    def _collect_busy_widgets(self):
        """Widgets to freeze during background detect work."""
        w = []
        for name in [
            "nameLineEdit", "ipLineEdit", "gatewayLineEdit", "apnLineEdit",
            "simLineEdit", "emailLineEdit",
        ]:
            if hasattr(self, name):
                w.append(getattr(self, name))
        # dynamic / created in code
        w += [
            self.detectGatewayButton, self.detectApnButton, self.detectCellButton,
            self.ifaceCombo, getattr(self, "imsiLineEdit", None),
            getattr(self, "imeiLineEdit", None), getattr(self, "iccidLineEdit", None),
            getattr(self, "simDetectedLine", None),  # ← added
            self.saveButton
        ]
        # filter Nones
        self._busy_widgets = [x for x in w if x is not None]

    # inside DeviceSettingsDialog
    def _cell_text(self, row, col):
        it = self.cellularTable.item(row, col)
        return (it.text().strip() if it else "")

    def _collect_cellular_rows(self) -> list[dict]:
        rows = []
        if not hasattr(self, "cellularTable") or self.cellularTable is None:
            return rows

        # Map your columns → fields. Adjust indices to your table:
        COL_IFACE   = 0
        COL_IP      = 1
        COL_STATUS  = 2
        COL_PROTO   = 3
        COL_IMSI    = 4
        COL_IMEI    = 5
        COL_ICCID   = 6
        COL_APN     = 7
        COL_SIM     = 8
        COL_MODEMFW = 9  # if you have it; otherwise remove

        for r in range(self.cellularTable.rowCount()):
            d = {
                "interface":       self._cell_text(r, COL_IFACE),
                "ip_addr":         self._cell_text(r, COL_IP) or "unassigned",
                "status":          self._cell_text(r, COL_STATUS),
                "protocol":        self._cell_text(r, COL_PROTO),
                "imsi":            self._cell_text(r, COL_IMSI),
                "imei":            self._cell_text(r, COL_IMEI),
                "iccid":           self._cell_text(r, COL_ICCID),
                "apn":             self._cell_text(r, COL_APN),
                "sim":             self._cell_text(r, COL_SIM),
                "modem_firmware":  self._cell_text(r, COL_MODEMFW),
            }
            # keep only non-empty rows (has interface or any meaningful cell field)
            if d["interface"] or any(d[k] for k in ("ip_addr","status","protocol","imsi","imei","iccid","apn","sim","modem_firmware")):
                rows.append(d)
        return rows

    def handle_detect_all(self):
        ip = self.ipLineEdit.text().strip()
        if not ip:
            QtWidgets.QMessageBox.warning(self, "Missing IP", "Please enter the router IP first.")
            return

        self._set_busy(True)
        self.overlay.show(); self.overlaySpinner.start()

        # HARD STOP after 30s (adjust as needed)
        self._detectAllWatchdog.start(30_000)

        def work():
            gw = None; details = []; apn = None; err = None
            try:
                username, password = get_ssh_credentials()
                if not (username and password):
                    raise RuntimeError("SSH credentials not set.")

                # 1) Gateway
                try:
                    gw_ip, gw_if = detect_default_gateway(ip, username, password, vrf=None)
                    gw =f"{gw_ip} ({gw_if})" if gw_ip and gw_if else (gw_ip or "")

                except Exception:
                    gw = None

                # 2) Cellular
                try:
                    details = fetch_all_cellular_details(ip, timeout=6)
                except Exception:
                    details = []

                # 3) APN
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(ip, username=username, password=password,
                                look_for_keys=False, allow_agent=False,
                                timeout=6, banner_timeout=10, auth_timeout=8)
                    sh = ssh.invoke_shell(); time.sleep(0.4)
                    if sh.recv_ready(): _ = sh.recv(65535)

                    def send(cmd):
                        sh.send(cmd + "\n"); time.sleep(0.45)
                        out = ""
                        while sh.recv_ready():
                            out += sh.recv(65535).decode(errors="ignore")
                        return out

                    brief = send("show ip interface brief")
                    slot = _find_cellular_slot_from_brief(brief)
                    big = ""
                    if slot:
                        for cmd in (f"show cellular {slot} profile",
                                    f"show cellular {slot} lte profile",
                                    f"show cellular {slot} all",
                                    f"show running-config | section ^cellular {slot}",
                                    "show running-config | include apn"):
                            big += "\n--- " + cmd + " ---\n" + send(cmd)
                    try: sh.close()
                    except: pass
                    try: ssh.close()
                    except: pass

                    _apn = _parse_apn(big)
                    apn = _apn if _apn else None
                except Exception:
                    apn = None

            except Exception as e:
                err = f"{type(e).__name__}: {e}"

            # Emit back to UI thread no matter what
            self.detectSignals.allDetected.emit(gw, details, apn, err)

        # 🚀 start the background worker
        threading.Thread(target=work, daemon=True).start()
    
    @QtCore.pyqtSlot(object, list, object, object)
    def _on_all_detected(self, gw, details, apn, err):
        self._detectAllWatchdog.stop()        # ← stop watchdog
        if gw:
            self.gatewayLineEdit.setText(str(gw))
        if details:
            self._set_interface_list(details, select_best=True)
            # persist just like you already do...
            try:
                if self.device and self.device.get("id"):
                    apn_txt = self.apnLineEdit.text().strip()
                    to_save = []
                    for d in self._cell_details:
                        dd = dict(d)
                        if apn_txt and not dd.get("apn"):
                            dd["apn"] = apn_txt
                        to_save.append(dd)
                    replace_device_cellular(self.device["id"], to_save)
                    best = max(self._cell_details, key=_score_iface) if self._cell_details else {}
                    update_device_primary_cellular(self.device["id"], best or {}, apn_txt)
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Warning",
                    f"Saved UI, but failed to store cellular rows:\n{e}")

        if apn:
            self.apnLineEdit.setText(apn)

        self.overlaySpinner.stop(); self.overlay.hide()
        self._set_busy(False)

        msg = [
            "Detect All finished:",
            f"• Gateway: {'OK' if gw else '—'}",
            f"• Cellular: {len(details) if details else 0} interface(s)",
            f"• APN: {apn if apn else '—'}",
        ]
        if err: msg.append(f"\nNote: {err}")
        QtWidgets.QMessageBox.information(self, "Detect All", "\n".join(msg))

    def _detect_all_timed_out(self):
        # UI must recover even if worker thread is still stuck
        self.overlaySpinner.stop(); self.overlay.hide()
        self._set_busy(False)
        QtWidgets.QMessageBox.warning(
            self, "Detect All",
            "Timed out after 30 seconds. The device may be slow or unreachable.\n"
            "Partial results (if any) were not applied."
        )

    def _on_sim_changed(self, txt: str):
        """Keep the edited SIM in sync with the selected interface row and refresh label."""
        iface = self.selected_interface or ""
        if not iface or not self._cell_details:
            return

        for d in self._cell_details:
            if d.get("interface", "") == iface:
                d["sim"] = txt.strip()
                break

        # refresh the current combo-row text so it shows SIM live
        idx = self.ifaceCombo.currentIndex()
        if 0 <= idx < self.ifaceCombo.count():
            self.ifaceCombo.setItemText(idx, self._format_iface_item(self._cell_details[idx]))

    def _set_busy(self, on: bool):
        """Show centered overlay spinner and disable inputs."""
        # show overlay on top of the whole dialog
        self.overlay.setGeometry(self.rect())
        self.overlay.raise_()
        self.overlay.setVisible(on)
        if on:
            self.overlaySpinner.start()
        else:
            self.overlaySpinner.stop()

        # disable/enable fields (keep Cancel enabled so user can close)
        for w in self._busy_widgets:
            w.setEnabled(not on)

    def showEvent(self, event):
        super().showEvent(event)
        if not self._prefill_started:
            self._prefill_started = True
            ip = self.ipLineEdit.text().strip()
            if ip:
                # Prefill silently after the dialog is visible
                QtCore.QTimer.singleShot(0, self._prefill_cellular_ids_silent)

    def _prefill_cellular_ids_silent(self):
        ip = self.ipLineEdit.text().strip()
        if not ip:
            return
        def run():
            try:
                details = fetch_all_cellular_details(ip)
                self.detectSignals.prefillDetected.emit(details)
            except Exception:
                pass
        threading.Thread(target=run, daemon=True).start()

    @pyqtSlot(list)
    def _apply_cellular_ids_silent(self, details):
        if not details:
            return
        # we don’t merge anymore for UI; just show the current eligible set
        self._set_interface_list(details, select_best=True)

    def _format_iface_item(self, d: dict) -> str:
        name = d.get("interface") or "Cellular?"
        ip = (d.get("ip") or "").strip()
        label_ip = ip if ip and ip.lower() != "unassigned" else "unassigned"
        sim = (d.get("sim") or "").strip() or "—"
        return f"{name} ({label_ip}) • SIM: {sim}"

    def _update_iface_status(self, d: dict):
        # consider protocol 'up' or status containing 'up' as link-up
        protocol = (d.get("protocol") or "").lower()
        status   = (d.get("status") or "").lower()
        is_up = ("up" in protocol) or (status == "up")
        color = "#10b981" if is_up else "#9ca3af"  # green or gray
        text  = "● up" if is_up else "● down"
        self.ifaceStatus.setText(text)
        self.ifaceStatus.setStyleSheet(f"QLabel {{ color:{color}; font-size:14px; }}")

    def _apply_detail_to_fields(self, d: dict):
        if hasattr(self, "imsiLineEdit"):  self.imsiLineEdit.setText(d.get("imsi",""))
        if hasattr(self, "imeiLineEdit"):  self.imeiLineEdit.setText(d.get("imei",""))
        if hasattr(self, "iccidLineEdit"): self.iccidLineEdit.setText(d.get("iccid",""))

        if hasattr(self, "simLineEdit"):
            new_sim = (d.get("sim") or "").strip()
            cur_sim = self.simLineEdit.text().strip()
            # only set if we have something meaningful to show and we won’t clobber user typing
            if new_sim and not getattr(self, "_user_edited_sim", False):
                if not cur_sim:
                    self.simLineEdit.blockSignals(True)
                    self.simLineEdit.setText(new_sim)
                    self.simLineEdit.blockSignals(False)

        self._update_iface_status(d)
        self.selected_interface = d.get("interface","")

    def _set_interface_list(self, details: list, select_best=True):
        eligible = [dict(d) for d in (details or []) if _is_qualified_cell_row(d)]
        self._cell_details = eligible

        self.ifaceCombo.blockSignals(True)
        self.ifaceCombo.clear()

        if not eligible:
            self._update_iface_status({})  # will show gray "down"
            self.ifaceCombo.blockSignals(False)
            return

        for d in eligible:
            self.ifaceCombo.addItem(self._format_iface_item(d))
        self.ifaceCombo.blockSignals(False)

        idx = 0
        if select_best:
            try:
                idx = max(range(len(eligible)), key=lambda i: _score_iface(eligible[i]))
            except ValueError:
                idx = 0
        self.ifaceCombo.setCurrentIndex(idx)
        self._apply_detail_to_fields(eligible[idx])

    def _on_iface_changed(self, idx: int):
        if idx < 0 or idx >= len(self._cell_details):
            return
        row = self._cell_details[idx]

        # parse "(X.Y.Z.W)" from the combo text
        text = self.ifaceCombo.currentText()
        m = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", text)
        parsed_ip = m.group(1) if m else ""

        row["ip_addr"] = parsed_ip
        row["ip"] = parsed_ip
        self._apply_detail_to_fields(self._cell_details[idx])

    # ---------- create IMSI/IMEI/ICCID rows ----------
    def _ensure_id_fields(self, main_vbox: QtWidgets.QVBoxLayout):
        # Reuse or create the fields
        self.imsiLineEdit  = getattr(self, "imsiLineEdit",  None) or QtWidgets.QLineEdit()
        self.imeiLineEdit  = getattr(self, "imeiLineEdit",  None) or QtWidgets.QLineEdit()
        self.iccidLineEdit = getattr(self, "iccidLineEdit", None) or QtWidgets.QLineEdit()
        self.simLineEdit   = getattr(self, "simLineEdit",   None) or QtWidgets.QLineEdit()

        # IDs are detected and locked; SIM should be editable
        for w in (self.imsiLineEdit, self.imeiLineEdit, self.iccidLineEdit):
            w.setReadOnly(True)
            w.setPlaceholderText("— detected after clicking ‘Detect Cellular’ —")

        self.simLineEdit.setReadOnly(False)
        self.simLineEdit.setPlaceholderText("SIM Number")

        # object names (handy if you style/test)
        self.imsiLineEdit.setObjectName("imsiLineEdit")
        self.imeiLineEdit.setObjectName("imeiLineEdit")
        self.iccidLineEdit.setObjectName("iccidLineEdit")
        self.simLineEdit.setObjectName("simLineEdit")

        # layout
        grid = QtWidgets.QGridLayout()
        grid.setVerticalSpacing(6)
        grid.setHorizontalSpacing(8)
        grid.addWidget(QtWidgets.QLabel("IMSI"),  0, 0); grid.addWidget(self.imsiLineEdit,  0, 1)
        grid.addWidget(QtWidgets.QLabel("IMEI"),  1, 0); grid.addWidget(self.imeiLineEdit,  1, 1)
        grid.addWidget(QtWidgets.QLabel("ICCID"), 2, 0); grid.addWidget(self.iccidLineEdit, 2, 1)
        grid.addWidget(QtWidgets.QLabel("SIM"),   3, 0); grid.addWidget(self.simLineEdit,   3, 1)

                # NEW: Hostname / IOS / Firmware (IOS+Firmware read-only; fetched via SSH)
        self.hostnameLineEdit = getattr(self, "hostnameLineEdit", None) or QtWidgets.QLineEdit()
        self.iosLineEdit      = getattr(self, "iosLineEdit",      None) or QtWidgets.QLineEdit()
        self.fwLineEdit       = getattr(self, "fwLineEdit",       None) or QtWidgets.QLineEdit()
        self.iosLineEdit.setReadOnly(True); self.fwLineEdit.setReadOnly(True)
        self.iosLineEdit.setPlaceholderText("— detected via SSH —")
        self.fwLineEdit.setPlaceholderText("— detected via SSH —")

        grid2 = QtWidgets.QGridLayout()
        grid2.setVerticalSpacing(6); grid2.setHorizontalSpacing(8)
        grid2.addWidget(QtWidgets.QLabel("Hostname"), 0, 0); grid2.addWidget(self.hostnameLineEdit, 0, 1)
        grid2.addWidget(QtWidgets.QLabel("IOS"),      1, 0); grid2.addWidget(self.iosLineEdit,      1, 1)
        grid2.addWidget(QtWidgets.QLabel("Firmware"), 2, 0); grid2.addWidget(self.fwLineEdit,       2, 1)
        
        main_vbox.insertLayout(6, grid)
        main_vbox.insertLayout(7, grid2)

        # when SIM text changes, keep our in-memory detail list in sync
        self.simLineEdit.textChanged.connect(self._on_sim_changed)

    # inside DeviceSettingsDialog
    def get_data(self) -> dict:
        # Safe helpers
        def _txt(obj_name: str) -> str:
            w = getattr(self, obj_name, None)
            if isinstance(w, QtWidgets.QLineEdit):
                return w.text().strip()
            # fallback: find by objectName in UI if not attached as attribute
            w = self.findChild(QtWidgets.QLineEdit, obj_name)
            return w.text().strip() if w else ""

        dev_id = getattr(self, "device_id", None) or (self.device.get("id") if isinstance(self.device, dict) else None)
        iface   = self.ifaceCombo.currentText().strip() if hasattr(self, "ifaceCombo") else ""
        iface_name = iface.split(" (", 1)[0].strip() if iface else ""

        # Base device fields from your simple UI
        data = {
            "id":            dev_id,
            "name":          _txt("nameLineEdit"),
            "ip":            _txt("ipLineEdit"),
            "gateway":       _txt("gatewayLineEdit"),
            "apn":           _txt("apnLineEdit"),
            "email":         _txt("emailLineEdit"),
            "hostname":      getattr(self, "hostnameLineEdit", None) and _txt("hostnameLineEdit") or "",
            "ios_version":   getattr(self, "iosLineEdit", None) and _txt("iosLineEdit") or "",
            "modem_firmware": getattr(self, "fwLineEdit", None) and _txt("fwLineEdit") or "",
        }

        # Editable SIM from the dialog top (this is your primary SIM field)
        sim_edit = _txt("simLineEdit")
        if sim_edit:
            data["sim"] = sim_edit
        
        # Pull what we know about the selected interface from detect / saved rows
        selected = {}
        try:
            # _cell_details is a list of dicts added either from DB (get_device_cellular)
            # or detect result. Pick the one that matches current iface.
            for d in getattr(self, "_cell_details", []) or []:
                if d.get("interface", "")  == iface_name:
                    selected = dict(d)
                    break
        except Exception:
            selected = {}

        # Build one cellular_details row merging selected + edits
        row = {
            "interface": iface_name or selected.get("interface", ""),
            "ip_addr":   selected.get("ip", "") or "unassigned",   # DB expects ip_addr
            "status":    selected.get("status", ""),
            "protocol":  selected.get("protocol", ""),
            "imsi":      _txt("imsiLineEdit")  or selected.get("imsi", ""),
            "imei":      _txt("imeiLineEdit")  or selected.get("imei", ""),
            "iccid":     _txt("iccidLineEdit") or selected.get("iccid", ""),
            "apn":       _txt("apnLineEdit")   or selected.get("apn", ""),
            "sim":       sim_edit or selected.get("sim", ""),
        }

        # Only include if we have an interface or any meaningful field
        details = []
        if row["interface"] or any(row[k] for k in ("imsi","imei","iccid","apn","sim")):
            details.append(row)

        if details:
            data["cellular_details"] = details

        return data

    @pyqtSlot(list)
    def on_cellular_detected(self, details):
        self.overlaySpinner.stop(); self.overlay.hide(); self._set_busy(False)

        # UI: only eligible will be shown
        self._set_interface_list(details, select_best=True)
        shown = list(self._cell_details)

        best = {}
        try:
            if shown:
                best = max(shown, key=_score_iface)
        except ValueError:
            best = shown[0] if shown else {}

        if best:
            self._apply_detail_to_fields(best)

        # persist: purge then insert only what we show
        try:
            if self.device and self.device.get("id"):
                apn = self.apnLineEdit.text().strip()
                to_save = []
                for d in shown:
                    dd = dict(d)
                    if apn and not dd.get("apn"):
                        dd["apn"] = apn
                    to_save.append(dd)
                replace_device_cellular(self.device["id"], to_save)
                update_device_primary_cellular(self.device["id"], best or {}, apn)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Warning", f"Saved UI, but failed to store cellular rows:\n{e}")

        QtWidgets.QMessageBox.information(
            self, "Cellular",
            f"Saved {len(shown)} interface(s) that meet the criteria."
            + (f"\nPrimary: {best.get('interface','?')} ({best.get('ip','')})." if best else "\nNo eligible interface.")
        )

    def _resize_event_forward(self, event):
        super().resizeEvent(event)
        if hasattr(self, "overlay") and hasattr(self, "overlaySpinner"):
            self.overlay.setGeometry(self.rect())
            self.overlay.raise_()
            self.overlaySpinner.setGeometry(self.overlay.width()//2-40,
                                            self.overlay.height()//2-40, 80, 80)

    # -------------- Detect actions --------------
    def handle_detect_cellular(self):
        ip = self.ipLineEdit.text().strip()
        if not ip:
            QtWidgets.QMessageBox.warning(self, "Missing IP", "Please enter the router IP first.")
            return

        self._set_busy(True)  # show overlay + disable fields

        def run():
            try:
                details = fetch_all_cellular_details(ip)
                self.detectSignals.cellularDetected.emit(details)
            except Exception as e:
                self.detectSignals.detectFailed.emit(str(e))

        threading.Thread(target=run, daemon=True).start()

    def handle_detect_apn(self):
        ip = self.ipLineEdit.text().strip()
        if not ip:
            QtWidgets.QMessageBox.warning(self, "Missing IP", "Please enter the router IP first.")
            return

        self.overlay.show(); self.overlaySpinner.start()
        self._set_busy(True)     
        def run():
            ssh = None
            try:
                username, password = get_ssh_credentials()
                if not username or not password:
                    self.detectSignals.detectFailed.emit("SSH credentials not set.")
                    return

                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password,
                            look_for_keys=False, allow_agent=False)

                sh = ssh.invoke_shell()
                time.sleep(0.4)
                if sh.recv_ready():
                    _ = sh.recv(65535)

                _shell_send_and_read(sh, "terminal length 0")
                brief = _shell_send_and_read(sh, "show ip interface brief")

                slot = _find_cellular_slot_from_brief(brief)
                if not slot:
                    try: sh.close()
                    except: pass
                    ssh.close()
                    self.detectSignals.detectFailed.emit("No Cellular interface found in 'show ip interface brief'.")
                    return

                outputs = []
                for cmd in [
                    f"show cellular {slot} profile",
                    f"show cellular {slot} lte profile",
                    f"show cellular {slot} all",
                    f"show running-config | section ^cellular {slot}",
                    "show running-config | include apn",
                ]:
                    outputs.append(f"\n--- {cmd} ---\n" + _shell_send_and_read(sh, cmd))

                try: sh.close()
                except: pass
                ssh.close()

                big = "".join(outputs)
                apn = _parse_apn(big)
                if apn:
                    self.detectSignals.apnDetected.emit(apn)
                else:
                    self.detectSignals.detectFailed.emit(
                        "Could not detect APN from device output.\n"
                        "Checked: show cellular <slot> profile / lte profile / all, and running-config."
                    )

            except Exception as e:
                try:
                    if ssh: ssh.close()
                except: pass
                self.detectSignals.detectFailed.emit(f"{type(e).__name__}: {e}")

        threading.Thread(target=run, daemon=True).start()

    def on_apn_detected(self, apn):
        self.apnLineEdit.setText(apn)
        self._set_busy(False) 
        self.overlaySpinner.stop(); self.overlay.hide()
        QtWidgets.QMessageBox.information(self, "APN Detected", f"Detected APN: {apn}")

    def on_gateway_detected(self, gateway):
        self.gatewayLineEdit.setText(gateway)
        self._set_busy(False)   
        self.overlaySpinner.stop(); self.overlay.hide()
        QtWidgets.QMessageBox.information(self, "Gateway Detected", f"Detected Gateway: {gateway}")

    def on_apn_failed(self, message):
        self.overlaySpinner.stop(); self.overlay.hide()
        self._set_busy(False)
        QtWidgets.QMessageBox.warning(self, "Detection Failed", message)

    def handle_detect_gateway(self):
        ip = self.ipLineEdit.text().strip()
        if not ip:
            QtWidgets.QMessageBox.warning(self, "Missing IP", "Please enter the router IP first.")
            return
        self.overlay.show(); self.overlaySpinner.start()
        self._set_busy(True)
        def run():
            try:
                username, password = get_ssh_credentials()
                if not username or not password:
                    self.detectSignals.detectFailed.emit("SSH credentials not set.")
                    return
                gw_ip, gw_if = detect_default_gateway(ip, username, password, vrf=None)
                gw = f"{gw_ip} ({gw_if})" if gw_ip and gw_if else (gw_ip or "")
                if gw:
                    self.detectSignals.gatewayDetected.emit(gw)
                else:
                    self.detectSignals.detectFailed.emit("Gateway of last resort is not set.")
            except Exception as e:
                self.detectSignals.detectFailed.emit(f"Gateway detect error: {e}")

        threading.Thread(target=run, daemon=True).start()

# ---------- Main window ----------
class CiscoSMSMonitorApp(QtWidgets.QMainWindow):
    tunnelResultsReady = QtCore.pyqtSignal(list, list, str)
    def __init__(self):
        super().__init__()
        ui_file = resource_path("combined_sms_monitor.ui")
        uic.loadUi(ui_file, self)
        self.setWindowIcon(QIcon(resource_path("icons/cisco.png")))
        self.statusBar()
        self._view_devices = []
        self._sim_pending = {}     # row_idx -> True (marker that we have a pending SIM refresh)
        # track recent outgoing-sender events (ip, t)
        from collections import deque
        self._recent_senders = deque(maxlen=200)   # stores (lan_ip, ts_seconds)
        self._senders_lock = threading.Lock()

        # --- after uic.loadUi(ui_file, self) ---
        # Bind tabs by name (these must exist in the .ui)
        self.tabCapture = self.findChild(QtWidgets.QWidget, "tabCapture")
        if not isinstance(self.tabCapture, QtWidgets.QWidget):
            raise RuntimeError("tabCapture not found in UI (check objectName in .ui)")

        # Try common objectNames for the Live SMS table, then fall back by type
        self.smsCaptureTable = (
            self.tabCapture.findChild(QtWidgets.QTableWidget, "smsCaptureTable")
            or self.tabCapture.findChild(QtWidgets.QTableWidget, "liveSmsTable")
            or self.tabCapture.findChild(QtWidgets.QTableWidget, "smsTable")  # if you reused the name
        )

        if not isinstance(self.smsCaptureTable, QtWidgets.QTableWidget):
            # last resort: pick the first QTableWidget inside tabCapture
            candidates = self.tabCapture.findChildren(QtWidgets.QTableWidget)
            self.smsCaptureTable = candidates[0] if candidates else None

        if not isinstance(self.smsCaptureTable, QtWidgets.QTableWidget):
            raise RuntimeError("Live SMS QTableWidget not found inside tabCapture. "
                            "Open the .ui and set a unique objectName (e.g. 'smsCaptureTable').")

        print("[UI] Live table bound as:", self.smsCaptureTable.objectName())

        # Devices tab widgets
        self.deviceSearchLineEdit = self.tabDevices.findChild(QtWidgets.QLineEdit, "searchLineEdit")
        # SMS Inbox tab
        self.inboxSearchLineEdit = self.tabSms.findChild(QtWidgets.QLineEdit, "searchLineEdit")
        self.smsInboxTable = self.tabSms.findChild(QtWidgets.QTableWidget, "smsTable")

        # ✅ Assert and log
        print("[LIVE-UI] tabCapture:", type(self.tabCapture).__name__)
        print("[LIVE-UI] smsCaptureTable:", type(self.smsCaptureTable).__name__)
        if not isinstance(self.smsCaptureTable, QtWidgets.QTableWidget):
            # fallback creation so we always have a table to draw on
            self.smsCaptureTable = QtWidgets.QTableWidget(self.tabCapture)
            lay = self.tabCapture.layout() or QtWidgets.QVBoxLayout(self.tabCapture)
            if self.tabCapture.layout() is None:
                self.tabCapture.setLayout(lay)
            lay.addWidget(self.smsCaptureTable)

        # make sure headers are visible and grid shows
        self.smsCaptureTable.horizontalHeader().setVisible(True)
        self.smsCaptureTable.verticalHeader().setVisible(False)
        self.smsCaptureTable.setShowGrid(True)
        # Build device table quickly
        self._setup_tunnels_tab()          # <— create the tab widgets (not inserted yet)
        self.dmvpnTable.setObjectName("dmvpnTable_real")
        self.eigrpTable.setObjectName("eigrpTable_real")
        self.tunnelDebugBtn.clicked.connect(self._show_last_tunnel_raw)
        self.tunnelResultsReady.connect(self._apply_tunnel_results)

        # Toolbar
        toolbar = self.addToolBar("Filter & Sort"); toolbar.setMovable(False)
        from PyQt5.QtWidgets import QComboBox, QCheckBox
        toolbar.addWidget(QLabel("Status:"))
        self.statusFilterCombo = QComboBox(); self.statusFilterCombo.addItems(["All", "Online", "Offline"])
        toolbar.addWidget(self.statusFilterCombo)

        self.simOnlyCheck = QCheckBox("SIM only"); toolbar.addWidget(self.simOnlyCheck)

        toolbar.addSeparator(); toolbar.addWidget(QLabel("Sort by:"))
        self.sortByCombo = QComboBox(); self.sortByCombo.addItems(["Device", "IP", "Status", "Gateway"])
        toolbar.addWidget(self.sortByCombo)

        self.sortOrderButton = QPushButton("Asc"); self.sortOrderButton.setCheckable(True)
        toolbar.addWidget(self.sortOrderButton)

        self.hubsOnlyCheck = QCheckBox("Hubs only"); toolbar.addWidget(self.hubsOnlyCheck)

        # Signals
        self.statusFilterCombo.currentIndexChanged.connect(self.apply_filters_and_sort)
        self.simOnlyCheck.toggled.connect(self.apply_filters_and_sort)
        self.sortByCombo.currentIndexChanged.connect(self.apply_filters_and_sort)
        self.hubsOnlyCheck.toggled.connect(self.apply_filters_and_sort)
        self.sortOrderButton.clicked.connect(self._toggle_sort_order)

        self.deviceTable.setSortingEnabled(True)
        self.deviceTable.horizontalHeader().sortIndicatorChanged.connect(lambda *_: None)
        
        # Menus
        settings_menu = self.menuBar().addMenu("Settings")
        db_settings_action = QtWidgets.QAction("Database Settings", self)
        db_settings_action.setIcon(QIcon(resource_path("icons/gear.jpg")))
        db_settings_action.triggered.connect(self.open_db_settings)
        settings_menu.addAction(db_settings_action)

        email_settings_action = QtWidgets.QAction("Email Settings", self)
        email_settings_action.setIcon(QIcon(resource_path("icons/gear.jpg")))
        email_settings_action.triggered.connect(self.open_email_settings_dialog)
        settings_menu.addAction(email_settings_action)

        ssh_settings_action = QtWidgets.QAction(QIcon("icons/ssh.png"),"Manage SSH Credentials", self)
        ssh_settings_action.triggered.connect(self.open_ssh_credentials_dialog)
        settings_menu.addAction(ssh_settings_action)

        notification_list = QtWidgets.QAction(QIcon(resource_path("icons/gear.jpg")),"Email Notification", self)
        notification_list.triggered.connect(self.open_email_notification)
        settings_menu.addAction(notification_list)

        # App state
        self.just_added_device = False
        self.worker_signals = WorkerSignals(self)
        self.worker_signals.deviceAdded.connect(self.update_devices_and_ui)
        # self.worker_signals.smsLogsFetched.connect(self.display_sms_log_dialog_result)
        self.worker_signals.refreshCompleted.connect(self.update_devices_after_refresh)

        # in CiscoSMSMonitorApp.__init__ (after creating self.worker_signals)
        self.worker_signals.smsLogsFetched.connect(
            self.display_sms_log_dialog_result,
            type=QtCore.Qt.QueuedConnection
        )

        self.sms_signal = SMSUpdateSignal()
        self.sms_signal.smsFetched.connect(self.on_sms_fetched)
        self.spinner = LoadingSpinner(self); self.spinner.setGeometry(self.rect())
        self.resizeEvent = self._resizeEvent

        # in CiscoSMSMonitorApp.__init__ (after self.spinner setup is fine)
        self._rowDetectWatchdog = QtCore.QTimer(self)
        self._rowDetectWatchdog.setSingleShot(True)
        self._rowDetectWatchdog.timeout.connect(self._detect_all_row_timed_out)

        self._sms_pool = ThreadPoolExecutor(max_workers=4)

        self._sms_pending = {}             # row_idx -> QTimer
        self._last_sms_col = None          # resolved at table-build time

        # Initial data
        self.devices = load_devices_from_db()
        self.sms_logs = []
        self.is_paused = False

        # Buttons
        self.addButton.clicked.connect(self.add_device)
        self.refreshButton.clicked.connect(self.refresh_devices_from_db)
        self.refreshButtonSMS.clicked.connect(self.fetch_all_devices)

        # Searches
        if self.deviceSearchLineEdit:
            self.deviceSearchLineEdit.textChanged.connect(self.filter_devices)
        if hasattr(self, "smsSearchLineEdit"):
            self.smsSearchLineEdit.textChanged.connect(self.filter_sms_logs)
        if self.inboxSearchLineEdit:
            self.inboxSearchLineEdit.textChanged.connect(self.filter_inbox_table)

        self.pauseButton.clicked.connect(self.toggle_pause)
        self.exportButton.clicked.connect(self.export_to_csv)

        # Build device table quickly
        self.load_devices(self.devices)
        self._ensure_tunnels_tab_visibility()

        # Start inbox fill on BG thread
        self.fetch_all_devices()

        # Syslog listener + timer
        self.start_syslog_listener()

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.fetch_all_devices)
        self.timer.start(5 * 60 * 1000)

    _autohub_checked = set()

    def _get_column_index(self, header_text: str):
        """
        Return the 0-based column index in deviceTable whose header matches
        `header_text` (case-insensitive). Returns None if not found.
        """
        if not hasattr(self, "deviceTable") or self.deviceTable is None:
            return None
        wanted = (header_text or "").strip().lower()
        for i in range(self.deviceTable.columnCount()):
            hdr = self.deviceTable.horizontalHeaderItem(i)
            if hdr and hdr.text().strip().lower() == wanted:
                return i
        return None


    def _ensure_on_gui(self, fn, *args, **kwargs):
        """
        Run `fn` on the GUI thread (useful when called from worker threads).
        """
        app_thread = QtWidgets.QApplication.instance().thread()
        if QtCore.QThread.currentThread() is not app_thread:
            QtCore.QTimer.singleShot(0, lambda: fn(*args, **kwargs))
            return False
        return True

    def _detect_all_row_timed_out(self):
        # UI must recover even if the worker thread is stuck
        try: self.spinner.stop()
        except: pass
        QtWidgets.QMessageBox.warning(
            self, "Detect All",
            "Timed out after 30 seconds. The device may be slow or unreachable.\n"
            "Partial results (if any) were not applied."
        )

    def _start_sim_refresh(self, row_idx: int, ip: str):
        col = self._col_index_e("SIM")
        if col == -1:
            return
        self._sim_pending[row_idx] = True

        # --- create a centered spinner with a parent so it never becomes a window
        container = QtWidgets.QWidget(self.deviceTable)
        lay = QtWidgets.QHBoxLayout(container)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        lbl = QtWidgets.QLabel(container)          # parented!
        lbl.setAlignment(Qt.AlignCenter)
        mv = QMovie(resource_path("icons/spinner.gif"))
        if not mv.isValid():
            # graceful fallback if the gif isn't found
            lbl.setText("…")
        else:
            lbl.setMovie(mv)
            mv.start()

        # keep refs so GC doesn’t stop it
        container._spinner_label = lbl
        container._spinner_movie = mv

        lay.addStretch(1)
        lay.addWidget(lbl, 0, Qt.AlignCenter)
        lay.addStretch(1)

        self.deviceTable.setCellWidget(row_idx, col, container)

        def worker():
            sim_text = ""
            try:
                dev = self._find_device_by_ip(ip)
                if dev and dev.get("id"):
                    sim_text = fetch_latest_sim_from_db(dev["id"]) or (dev.get("sim") or "")
            except Exception:
                try:
                    dev = self._find_device_by_ip(ip)
                    sim_text = dev.get("sim") or ""
                except Exception:
                    sim_text = ""
            QtCore.QTimer.singleShot(0, lambda: self._finish_sim_refresh(row_idx, ip, sim_text))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_sim_refresh(self, row_idx: int, ip: str, sim_text: str):
        """Replace spinner with the SIM text."""
        self._sim_pending.pop(row_idx, None)
        col = self._col_index("SIM")
        if col == -1:
            return

        # remove spinner if present
        w = self.deviceTable.cellWidget(row_idx, col)
        if w:
            try:
                mv = getattr(w, "movie", None)
                if mv: mv.stop()
            except:
                pass
            self.deviceTable.removeCellWidget(row_idx, col)
            w.deleteLater()

        # set final text
        item = QTableWidgetItem(sim_text or "")
        item.setTextAlignment(Qt.AlignCenter)
        self.deviceTable.setItem(row_idx, col, item)

        # also sync the in-memory device copy
        dev = self._find_device_by_ip(ip)
        if dev is not None:
            dev["sim"] = sim_text or dev.get("sim") or ""

    def _resolve_recipient(self, to_text: str) -> str:
        """Return a dialable number. Accepts raw number or device name."""
        s = (to_text or "").strip()
        if is_phone_number(s):                 # already a number
            return s
        # try device name (case-insensitive)
        dev = next((d for d in self.devices if d.get("name","").lower() == s.lower()), None)
        if dev:
            sim = (dev.get("sim") or "").strip()
            if sim:
                return sim
        return ""  # unknown

    def _show_last_tunnel_raw(self):
        try:
            with open("tunnel_debug.txt", "r", encoding="utf-8") as f:
                txt = f.read()
        except Exception:
            txt = "(No captured raw outputs yet. Click Refresh first.)"
        _show_text_dialog(self, "Tunnel debug (raw outputs)", txt)

    def _start_row_fetch(self, row_idx: int, ip: str, timeout_ms: int = 12000):
        if self._last_sms_col is None:
            self._last_sms_col = _col_index(self, "Last SMS", default=6) or 6  # fallback
        spin = _make_cell_spinner(self)
        self.deviceTable.setCellWidget(row_idx, self._last_sms_col, spin)

        # watchdog: if worker stalls, stop spinner and show timeout
        t = QtCore.QTimer(self)
        t.setSingleShot(True)
        t.timeout.connect(lambda ri=row_idx: self.sms_signal.smsFetched.emit(ri, "— timeout —"))
        t.start(timeout_ms)
        self._sms_pending[row_idx] = t

        # kick the worker (uses thread pool)
        self._sms_pool.submit(self._fetch_last_sms_worker, row_idx, ip)

    def _fetch_last_sms_worker(self, row_idx: int, ip: str):
        """Background: fetch last SMS, but ALWAYS emit a result."""
        txt = "No SMS"
        try:
            txt = _extract_sms_body(fetch_last_sms(ip)) or "No SMS"
        except Exception as e:
            txt = f"Error"
        finally:
            self.sms_signal.smsFetched.emit(row_idx, str(txt).strip())

    @pyqtSlot(int, str)
    def on_sms_fetched(self, row_idx: int, text: str):
        # row may be gone if table was rebuilt
        if row_idx < 0 or row_idx >= self.deviceTable.rowCount():
            # nothing to update; just forget this timer
            self._sms_pending.pop(row_idx, None)
            if not self._sms_pending:
                self.deviceTable.setSortingEnabled(True)
            return

        # cancel watchdog
        t = self._sms_pending.pop(row_idx, None)
        if t:
            try: t.stop()
            except: pass

        col = self._last_sms_col if self._last_sms_col is not None else 6

        # stop & remove spinner
        w = self.deviceTable.cellWidget(row_idx, col)
        if w:
            mv = getattr(w, "movie", None)
            if mv:
                mv.stop()
            # remove from the table and delete the widget
            self.deviceTable.removeCellWidget(row_idx, col)
            w.deleteLater()

        # now set the text cell
        self.deviceTable.setItem(row_idx, col, QtWidgets.QTableWidgetItem(text or ""))

        # ✅ allow sorting again only when all pending rows resolved
        if not self._sms_pending:
            self.deviceTable.setSortingEnabled(True)

    # ---------- Tunnel List tab (shown only if we have hubs) ----------
    def _setup_tunnels_tab(self):
        self._tunnels_tab_inserted = False
        self._tunnel_hub_map = {}

        self.tabTunnels = QWidget()
        lay = QVBoxLayout(self.tabTunnels)

        # top bar: hub picker + refresh
        top = QHBoxLayout()
        top.addWidget(QLabel("Hub:"))
        self.tunnelHubPicker = QComboBox()
        top.addWidget(self.tunnelHubPicker, 1)
        self.tunnelRefreshBtn = QPushButton("Refresh")
        top.addWidget(self.tunnelRefreshBtn)
        self.tunnelDebugBtn = QPushButton("Show Raw")
        top.addWidget(self.tunnelDebugBtn)
        top.addStretch(1)
        lay.addLayout(top)

        # NEW: lightweight status line so we can see what happened last refresh
        self.tunnelStatusLbl = QLabel("Ready")
        self.tunnelStatusLbl.setStyleSheet("color:#6b7280;")
        lay.addWidget(self.tunnelStatusLbl)  # ← add this

        lay.addWidget(QLabel("DMVPN / NHRP"))
        self.dmvpnTable = QTableWidget(0, 5)
        self.dmvpnTable.setHorizontalHeaderLabels(["Tunnel", "Peer (NHRP)", "NBMA", "State", "Uptime/Notes"])
        self.dmvpnTable.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.dmvpnTable)

        lay.addWidget(QLabel("EIGRP Neighbors"))
        self.eigrpTable = QTableWidget(0, 7)
        self.eigrpTable.setHorizontalHeaderLabels(["Address", "Interface", "Hold (sec)", "Uptime",
                                                "SRTT (ms)", "RTO", "Seq#"])
        self.eigrpTable.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.eigrpTable)

        self.tunnelRefreshBtn.clicked.connect(self.refresh_tunnels_now)
        self.tunnelHubPicker.currentIndexChanged.connect(self.refresh_tunnels_now)

    def _fallback_parse_dmvpn(self, text: str):
        # Works with your “show dmvpn” table exactly as pasted
        rows, tunnel = [], None
        ip = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
        for ln in (text or "").splitlines():
            s = ln.strip()
            if not s:
                continue
            m_if = re.search(r"\bInterface:\s*(Tunnel\S+)", s, re.I)
            if m_if:
                tunnel = m_if.group(1); continue
            if re.match(r"^#\s*Ent\b", s):  # header line
                continue
            m = re.search(rf"\b({ip})\s+({ip})\s+(UP|DOWN)\s+(\S+)\s+\S+\s*$", s, re.I)
            if m and tunnel:
                nbma, peer, state, uptime = m.groups()
                rows.append({"tunnel": tunnel, "peer": peer, "nbma": nbma,
                            "state": state.lower(), "note": uptime})
        return rows

    def _fallback_parse_eigrp(self, text: str):
        rows = []
        ip = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
        for ln in (text or "").splitlines():
            s = ln.strip()
            if not s or s.startswith(("EIGRP-IPv4", "H ", "(")):
                continue
            # with leading H column
            m = re.match(rf"^\d+\s+({ip})\s+(\S+)\s+(\d+)\s+([\w:]+)\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)\s*$", s)
            if not m:
                # without leading H
                m = re.match(rf"^({ip})\s+(\S+)\s+(\d+)\s+([\w:]+)\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)\s*$", s)
            if m:
                addr, iface, hold, uptime, srtt, rto, seq = m.groups()
                if iface.lower().startswith("tu"):
                    iface = "Tunnel" + re.sub(r"\D", "", iface)
                rows.append({"addr": addr, "iface": iface, "hold": hold,
                            "uptime": uptime, "srtt": srtt, "rto": rto, "seq": seq})
        return rows

    def _ensure_tunnels_tab_visibility(self):
        # hard kill the whole tab if hub SSH is disabled
        if not ALLOW_SSH_HUB_DETECT:
            if not hasattr(self, "_mainTabWidget"):
                self._mainTabWidget = self.findChild(QTabWidget)
            if getattr(self, "_tunnels_tab_inserted", False) and hasattr(self, "_mainTabWidget"):
                idx = self._mainTabWidget.indexOf(self.tabTunnels)
                if idx >= 0:
                    self._mainTabWidget.removeTab(idx)
                self._tunnels_tab_inserted = False
            return
        # find the QTabWidget that contains the existing tabs
        if not hasattr(self, "_mainTabWidget"):
            self._mainTabWidget = self.findChild(QTabWidget)
            if not self._mainTabWidget:
                return  # nothing to do if the UI has no tab widget

        hubs = [d for d in self.devices if d.get("is_hub")]
        if not hubs:
            # remove tab if inserted
            if getattr(self, "_tunnels_tab_inserted", False):
                idx = self._mainTabWidget.indexOf(self.tabTunnels)
                if idx >= 0:
                    self._mainTabWidget.removeTab(idx)
                self._tunnels_tab_inserted = False
            return

        # we have hubs → ensure the tab exists
        if not getattr(self, "_tunnels_tab_inserted", False):
            # place it right after "Live SMS Capture"
            after_idx = self._mainTabWidget.indexOf(self.tabCapture)
            insert_at = (after_idx + 1) if after_idx >= 0 else self._mainTabWidget.count()
            self._mainTabWidget.insertTab(insert_at, self.tabTunnels, "Tunnel list")
            self._tunnels_tab_inserted = True

        # populate hub picker
        self._tunnel_hub_map.clear()
        self.tunnelHubPicker.blockSignals(True)
        self.tunnelHubPicker.clear()
        for d in hubs:
            label = f"{d.get('name','Hub')} ({d.get('ip','?')})"
            self._tunnel_hub_map[label] = d
            self.tunnelHubPicker.addItem(label)
        self.tunnelHubPicker.blockSignals(False)

        # auto refresh on first show
        self.refresh_tunnels_now()

    def _run_cmds_single_shell(self, transport, cmds, *, timeout: int = 30) -> dict:
        """
        Step-proof IOS shell runner:
        - capture exact prompt once
        - no pre-command blank-line flush
        - stop only after we saw real content and the prompt line again
        """
        out_by_cmd = {c: "" for c in cmds}
        if not cmds:
            return out_by_cmd
        if not transport or not transport.is_active():
            raise RuntimeError("SSH transport not active")

        chan = transport.open_session(timeout=timeout)
        try:
            chan.get_pty(term='vt100', width=180, height=50)
            chan.invoke_shell()
            chan.settimeout(timeout)

            def _drain_all():
                buf = bytearray()
                while chan.recv_ready():
                    chunk = chan.recv(65535)
                    if not chunk:
                        break
                    buf.extend(chunk)
                return bytes(buf)

            # settle & capture exact prompt
            time.sleep(0.15); _drain_all()
            prompt_line = _capture_prompt(chan)
            if not prompt_line:
                prompt_line = b'#'

            # try enable if we were in exec
            if prompt_line.endswith(b'>'):
                chan.send('enable\n'); time.sleep(0.15)
                tmp = _drain_all()
                if b'assword' in tmp or b'assword' in tmp.lower():
                    chan.send('\n'); time.sleep(0.15); _drain_all()
                # recapture prompt (should be '#')
                prompt_line = _capture_prompt(chan) or prompt_line

            # disable paging once and flush any echo
            chan.send('terminal length 0\n'); time.sleep(0.15); _drain_all()

            more_pat = re.compile(br'--More--|\(q\)uit', re.I)

            for cmd in cmds:
                chan.send(cmd.rstrip() + '\n')
                time.sleep(0.04)  # nudge device to start output

                buf = bytearray()
                last_rx = time.time()
                saw_body = False

                while True:
                    if chan.recv_ready():
                        chunk = chan.recv(65535)
                        if not chunk:
                            break
                        buf.extend(chunk)
                        last_rx = time.time()

                        tail = bytes(buf[-2048:])

                        # auto page
                        if more_pat.search(tail):
                            chan.send(' ')
                            continue

                        # mark once we really saw content (command echo OR a line with ':' etc.)
                        if (cmd.encode() in tail) or (b':' in tail) or (b'\n' in tail):
                            # but ignore stray term length echoes
                            txt = tail.decode('utf-8', 'ignore')
                            if not _TERM_LEN_RE.search(txt):
                                saw_body = True

                        # stop only after body and prompt are seen
                        if saw_body:
                            # examine last line
                            last_nl = tail.rfind(b'\n')
                            last_line = tail[last_nl+1:] if last_nl != -1 else tail
                            if last_line.rstrip().endswith(prompt_line):
                                break
                    else:
                        if time.time() - last_rx > timeout:
                            break
                        time.sleep(0.04)

                raw = buf.decode('utf-8', 'ignore')

                # remove the first echoed command line (only that line)
                idx = raw.find(cmd)
                if idx != -1:
                    nl = raw.find('\n', idx)
                    if nl != -1:
                        raw = raw[nl+1:]

                # drop trailing prompt line (exact match)
                raw = re.sub(rf"\r?\n{re.escape(prompt_line.decode('utf-8','ignore'))}\s*$", "", raw)

                # strip pager & ANSI & term-length noise
                raw = re.sub(r'--More--|\(q\)uit', '', raw, flags=re.I)
                raw = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw)
                raw = _strip_term_len_noise(raw)

                out_by_cmd[cmd] = raw.strip()
            return out_by_cmd
        finally:
            try: chan.close()
            except Exception: pass

    def _run_cmd_new_session(
        self,
        transport: paramiko.Transport,
        cmd: str,
        *,
        prompt_end=(b'#', b'>'),
        timeout: int = 16
    ) -> str:
        """
        Open a NEW session channel on the existing SSH transport, run a single CLI
        command with paging disabled, and return cleaned output.
        - Tries 'enable' ONLY if at exec prompt ('>'); cancels if 'Password:' shown.
        - Handles pagers.
        """
        chan = transport.open_session(timeout=timeout)
        try:
            chan.get_pty(term='vt100', width=200, height=50)
            chan.invoke_shell()
            chan.settimeout(timeout)

            def _drain() -> bytes:
                buf = bytearray()
                try:
                    while chan.recv_ready():
                        data = chan.recv(65535)
                        if not data:
                            break
                        buf.extend(data)
                except Exception:
                    pass
                return bytes(buf)

            def _send(line: str):
                chan.send(line.rstrip() + '\n')

            time.sleep(0.2)
            banner = _drain()

            def _looks_exec_prompt(b: bytes) -> bool:
                lines = b.strip().splitlines()
                if not lines:
                    return False
                last = lines[-1].strip()
                return last.endswith(b'>') and (b' ' not in last)

            def _attempt_enable():
                _send('enable')
                time.sleep(0.15)
                buf = _drain()
                if b'Password:' in buf or b'password:' in buf:
                    _send('')
                    time.sleep(0.15)
                    _drain()

            if _looks_exec_prompt(banner):
                try:
                    _attempt_enable()
                except Exception:
                    pass

            _send('terminal length 0')
            _send(cmd)

            buf = bytearray()
            more_pat = re.compile(br'--More--|\(q\)uit', re.I)
            last_rx = time.time()

            while True:
                if chan.recv_ready():
                    chunk = chan.recv(65535)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    last_rx = time.time()

                    tail = bytes(buf[-512:])
                    if more_pat.search(tail):
                        chan.send(' ')
                        continue

                    tail_stripped = tail.rstrip()
                    if any(
                        tail_stripped.endswith(pe) or (b'\n' + pe) in tail_stripped
                        for pe in prompt_end
                    ):
                        break
                else:
                    if time.time() - last_rx > timeout:
                        break
                    time.sleep(0.05)

            raw = buf.decode(errors='ignore')
            cleaned_lines = []
            for ln in raw.splitlines():
                s = ln.strip()
                if not s:
                    continue
                if s.startswith('terminal length 0') or s == cmd or s.startswith(cmd + ' '):
                    continue
                if (s.endswith('#') or s.endswith('>')) and (' ' not in s) and (len(s) <= 80):
                    continue
                cleaned_lines.append(ln)

            return '\n'.join(cleaned_lines).strip()

        finally:
            try:
                chan.close()
            except Exception:
                pass

    def _get_selected_hub(self):
        label = self.tunnelHubPicker.currentText().strip()
        return self._tunnel_hub_map.get(label)

    # =========================
    # END-TO-END REFRESH (SAFE)
    # =========================

    def refresh_tunnels_now(self):
        """
        Thread-safe: fetch NHRP/DMVPN/EIGRP via one SSH session,
        parse rows, then marshal UI updates to the main thread.
        """
        from datetime import datetime
        import threading

        def set_status(txt, warn=False):
            if hasattr(self, "tunnelStatusLbl") and self.tunnelStatusLbl:
                self.tunnelStatusLbl.setText(txt)
                self.tunnelStatusLbl.setStyleSheet(f"color:{'#ef4444' if warn else '#6b7280'};")

        hub = self._get_selected_hub()
        if not hub:
            self._apply_tunnel_results([], [], "No hub selected")
            return

        ip   = hub.get("ip")
        name = hub.get("name", "Hub")

        # quick gates
        if not ALLOW_SSH_HUB_DETECT:
            self._apply_tunnel_results([], [], "SSH hub detection disabled")
            return
        if ip not in HUB_PROBE_ALLOWLIST:
            self._apply_tunnel_results([], [], f"Hub {ip} not in allow-list")
            return
        if not is_device_online(ip):
            self._apply_tunnel_results([], [], f"{ip} is offline / TCP 22 closed")
            return

        username, password = get_ssh_credentials()
        if not (username and password):
            self._apply_tunnel_results([], [], "SSH credentials not set")
            return

        set_status("Connecting…")

        def worker():
            # Always write a debug file you can open with “Show Raw”
            log_lines = [
                f"[{datetime.now().isoformat(timespec='seconds')}] Refresh for {name} ({ip})",
                f"Used NHRP cmd:  show ip nhrp",
                f"Used DMVPN cmd: show dmvpn",
                f"Used EIGRP cmd: show ip eigrp neighbors",
                "",
            ]
            outs = {"nhrp": "", "dmvpn": "", "eigrp": ""}

            try:
                cli = ssh_connect_resilient(ip, username, password,
                                            conn_timeout=10, banner_timeout=40, auth_timeout=25,
                                            tries=3, sleep_between=1.0)
                try:
                    t = cli.get_transport()
                    if not t or not t.is_active():
                        raise RuntimeError("SSH transport not active")
                    # one PTY shell, multiple commands, pager handled
                    outs = self._ssh_run_multi(t, [
                        "show ip nhrp",
                        "show dmvpn",
                        "show ip eigrp neighbors",
                    ], timeout=20)
                finally:
                    try: cli.close()
                    except: pass
            except Exception as e:
                log_lines.append(f"SSH ERROR: {type(e).__name__}: {e}")
                with open("tunnel_debug.txt", "w", encoding="utf-8") as f:
                    f.write("\n".join(log_lines) + "\n")
                # post failure to UI
                self._apply_tunnel_results([], [], f"SSH error: {e}")
                return

            # put raw in the debug file (matches what you pasted)
            log_lines += [
                "=== SHOW IP NHRP ===",
                outs.get("show ip nhrp","").rstrip(),
                "",
                "=== SHOW DMVPN ===",
                outs.get("show dmvpn","").rstrip(),
                "",
                "=== SHOW IP EIGRP NEIGHBORS ===",
                outs.get("show ip eigrp neighbors","").rstrip(),
                ""
            ]
            with open("tunnel_debug.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(log_lines) + "\n")

            # parse exactly your formats
            dmvpn_rows = self._parse_nhrp_or_dmvpn(
                outs.get("show ip nhrp",""),
                outs.get("show dmvpn","")
            )
            eigrp_rows = self._parse_eigrp_neighbors(
                outs.get("show ip eigrp neighbors","")
            )

            # helpful console prints (you saw “[PARSE] … rows: 12” in your logs)
            print(f"[PARSE] DMVPN rows: {len(dmvpn_rows)}")
            print(f"[PARSE] EIGRP rows: {len(eigrp_rows)}")

            # hand results to the UI thread
            self.tunnelResultsReady.emit(dmvpn_rows, eigrp_rows, "OK")

        threading.Thread(target=worker, daemon=True).start()


    def _apply_tunnel_results(self, dmvpn_rows, eigrp_rows, status_text):
        """
        ALWAYS called on the Qt (GUI) thread. If called off-thread, we re-invoke with QueuedConnection.
        """
        # If we’re not on the GUI thread, bounce this back to it.
        if QtCore.QThread.currentThread() != QtWidgets.QApplication.instance().thread():
            QtCore.QMetaObject.invokeMethod(
                self,
                "_apply_tunnel_results",
                QtCore.Qt.QueuedConnection,
                QtCore.Q_ARG(list, dmvpn_rows),
                QtCore.Q_ARG(list, eigrp_rows),
                QtCore.Q_ARG(str,  status_text),
            )
            return

        # Update status label
        if hasattr(self, "tunnelStatusLbl") and self.tunnelStatusLbl:
            warn = (status_text != "OK")
            self.tunnelStatusLbl.setText(status_text)
            self.tunnelStatusLbl.setStyleSheet(f"color:{'#ef4444' if warn else '#6b7280'};")

        # Fill tables (these painters NEVER no-op)
        try:
            self._fill_dmvpn_table(dmvpn_rows or [])
            self._fill_eigrp_table(eigrp_rows or [])
        except Exception as e:
            # even painter errors get surfaced
            if hasattr(self, "tunnelStatusLbl") and self.tunnelStatusLbl:
                self.tunnelStatusLbl.setText(f"UI error: {e}")
                self.tunnelStatusLbl.setStyleSheet("color:#ef4444;")


    def _ssh_run_multi(self, transport, cmds, *, timeout=20):
        """
        Minimal single-PTY command runner (pager aware) returning {cmd: output}.
        Keeps your earlier semantics but self-contained for this refresh path.
        """
        out = {c: "" for c in cmds}
        chan = transport.open_session(timeout=timeout)
        try:
            chan.get_pty(term='vt100', width=200, height=50)
            chan.invoke_shell()
            chan.settimeout(timeout)

            def drain():
                buf = bytearray()
                try:
                    while chan.recv_ready():
                        chunk = chan.recv(65535)
                        if not chunk:
                            break
                        buf.extend(chunk)
                except Exception:
                    pass
                return bytes(buf)

            def send(line):
                chan.send(line.rstrip() + "\n")

            # settle & (optional) enable
            import time, re
            time.sleep(0.25); banner = drain()
            def looks_exec(b: bytes):
                lines = b.strip().splitlines()
                return bool(lines and lines[-1].strip().endswith(b'>') and b' ' not in lines[-1])
            if looks_exec(banner):
                send("enable"); time.sleep(0.15); b = drain()
                if b"Password:" in b or b"password:" in b:
                    send("")  # cancel enable if it prompts

            # no paging
            send("terminal length 0"); time.sleep(0.1); _ = drain()
            more_pat = re.compile(br'--More--|\(q\)uit', re.I)

            for c in cmds:
                send(c)
                buf = bytearray(); last = time.time()
                while True:
                    if chan.recv_ready():
                        chunk = chan.recv(65535)
                        if not chunk:
                            break
                        buf.extend(chunk); last = time.time()
                        tail = bytes(buf[-512:])
                        if more_pat.search(tail):
                            chan.send(' ')
                            continue
                        # stop when we see a fresh prompt at line end
                        tail_stripped = tail.rstrip()
                        if tail_stripped.endswith(b'#') or tail_stripped.endswith(b'>'):
                            break
                    else:
                        if time.time() - last > timeout:
                            break
                        time.sleep(0.05)

                # clean echoes/prompts
                raw = buf.decode(errors="ignore")
                cleaned = []
                for ln in raw.splitlines():
                    s = ln.strip()
                    if not s:
                        continue
                    if s.startswith("terminal length 0") or s == c or s.startswith(c + " "):
                        continue
                    if (s.endswith('#') or s.endswith('>')) and (' ' not in s) and len(s) <= 80:
                        continue
                    cleaned.append(ln)
                out[c] = "\n".join(cleaned).strip()

            return out
        finally:
            try: chan.close()
            except: pass

    @QtCore.pyqtSlot(object, object, str)
    def _apply_tunnel_tables(self, dmvpn_rows, eigrp_rows, error_txt):
        self._fill_dmvpn_table(dmvpn_rows or [])
        self._fill_eigrp_table(eigrp_rows or [])
        if error_txt:
            self.tunnelStatusLbl.setText(f"Refresh error: {error_txt}")
            self.tunnelStatusLbl.setStyleSheet("color:#ef4444;")
        elif not dmvpn_rows and not eigrp_rows:
            self.tunnelStatusLbl.setText("No peers parsed. Click ‘Show Raw’ to inspect.")
            self.tunnelStatusLbl.setStyleSheet("color:#ef4444;")
        else:
            self.tunnelStatusLbl.setText(f"OK — DMVPN rows: {len(dmvpn_rows)}, EIGRP rows: {len(eigrp_rows)}")
            self.tunnelStatusLbl.setStyleSheet("color:#6b7280;")

    @QtCore.pyqtSlot()
    def _apply_on_gui_helper(self):
        # this body will be replaced dynamically before invoke in refresh_tunnels_now
        # we keep the slot only to have a stable QObject method for invokeMethod
        pass

    def _parse_eigrp_neighbors(self, text: str):
        """
        Returns list of dicts:
        {"addr": "172.16.1.200", "iface":"Tu1", "hold":"14",
        "uptime":"3d03h", "srtt":"43", "rto":"1704", "seq":"1682"}
        Matches your 'show ip eigrp neighbors' table.
        """
        import re
        rows = []
        ip = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
        for ln in (text or "").splitlines():
            s = ln.strip()
            if not s or s.startswith(("EIGRP-IPv4", "H ", "(")):
                continue
            # With leading H col:
            m = re.match(rf"^\d+\s+({ip})\s+(\S+)\s+(\d+)\s+([\w:]+)\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)\s*$", s)
            # Without H col:
            if not m:
                m = re.match(rf"^({ip})\s+(\S+)\s+(\d+)\s+([\w:]+)\s+(\d+)\s+(\d+)\s+\d+\s+(\d+)\s*$", s)
            if m:
                addr, iface, hold, uptime, srtt, rto, seq = m.groups()
                rows.append({"addr": addr, "iface": iface, "hold": hold,
                            "uptime": uptime, "srtt": srtt, "rto": rto, "seq": seq})
        return rows

    def _parse_nhrp_or_dmvpn(self, nhrp_text: str, dmvpn_text: str):
        """
        Returns list of dicts:
        {"tunnel": "Tunnel1", "peer": "172.16.1.200", "nbma": "192.168.255.200",
        "state": "up"/"down", "note": "3d18h" }
        Works with either 'show ip nhrp' (by pairing NBMA lines) and/or 'show dmvpn'.
        """
        rows = []

        # ---- First pass: DMVPN table (your sample) ----
        #   Interface: Tunnel1 ...
        #   <nbma> <peer>  UP/DOWN  <uptime>  D
        import re
        ip = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
        cur_tun = None
        for ln in (dmvpn_text or "").splitlines():
            s = ln.strip()
            if not s:
                continue
            m_if = re.search(r"\bInterface:\s*(Tunnel\S+)", s, re.I)
            if m_if:
                cur_tun = m_if.group(1); continue
            # NBMA, Peer, State, Uptime
            m = re.match(rf"^\s*({ip})\s+({ip})\s+(UP|DOWN)\s+(\S+)", s, re.I)
            if m and cur_tun:
                nbma, peer, st, updn = m.groups()
                rows.append({"tunnel": cur_tun, "peer": peer, "nbma": nbma,
                            "state": st.lower(), "note": updn})

        # ---- Fallback: pair NHRP blocks if DMVPN not present ----
        if not rows:
            cur_tun = None
            last_peer = None
            for ln in (nhrp_text or "").splitlines():
                s = ln.strip()
                if not s:
                    continue
                m_t = re.search(r"^Tunnel\d+", s, re.I)
                if m_t:
                    cur_tun = m_t.group(0)
                m_peer = re.search(rf"^({ip})/32\s+via\s+({ip})", s, re.I)
                if m_peer:
                    last_peer = m_peer.group(2)  # tunnel address is after 'via'
                    continue
                m_nbma = re.search(rf"NBMA address:\s*({ip})", s, re.I)
                if m_nbma and cur_tun and last_peer:
                    rows.append({"tunnel": cur_tun, "peer": last_peer,
                                "nbma": m_nbma.group(1), "state": "up", "note": ""})
                    last_peer = None

        return rows

    def parse_ip_nhrp(text: str):
        _IP = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
        """
        Parses blocks like:
        172.16.1.200/32 via 172.16.1.200
            Tunnel1 created 20:12:04, expire 00:05:15
            Type: dynamic, Flags: unique registered used nhop
            NBMA address: 192.168.255.200
        Returns list of dicts: tunnel, peer, nbma, state, uptime
        """
        rows, cur = [], {}
        for line in (text or "").splitlines():
            line = line.rstrip()

            m1 = re.match(rf"^\s*({_IP})/\d+\s+via\s+({_IP})\s*$", line)
            if m1:
                # start a new peer block
                if cur:
                    rows.append(cur)
                peer = m1.group(1)
                cur = {"peer": peer, "via": m1.group(2)}
                continue

            m2 = re.match(r"^\s*Tunnel(\d+)\s+created\s+([^,]+),", line, re.I)
            if m2:
                cur["tunnel"] = f"Tunnel{m2.group(1)}"
                cur["uptime"] = m2.group(2).strip()
                continue

            m3 = re.match(r"^\s*Type:\s*\S+,\s*Flags:\s*(.+?)\s*$", line, re.I)
            if m3:
                # use Flags as our 'state' column text
                cur["state"] = m3.group(1).strip()
                continue

            m4 = re.match(rf"^\s*NBMA address:\s*({_IP})\s*$", line, re.I)
            if m4:
                cur["nbma"] = m4.group(1)
                continue

        if cur:
            rows.append(cur)

        # Normalize / fill
        for r in rows:
            r.setdefault("tunnel", "Tunnel?")
            r.setdefault("state", "")
            r.setdefault("uptime", "")
            r["nbma"] = r.get("nbma", "")
        return rows


    def parse_eigrp_neighbors(text: str):
        _IP = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
        """
        Parses 'show ip eigrp neighbors' table (IOS classic style).
        Returns list of dicts with: address, iface, hold, uptime, srtt, rto, qcnt, seq
        """
        rows = []
        for line in (text or "").splitlines():
            # skip headers/blank
            if not line.strip() or "Neighbors for AS" in line or line.lstrip().startswith(("H ", "Address", "(")):
                continue
            # Example:
            # 7   172.16.1.206            Tu1       12 00:27:00   42  1512  0  1446
            m = re.match(
                rf"^\s*\d+\s+({_IP})\s+(\S+)\s+(\d+)\s+([\w:]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",
                line
            )
            if m:
                addr, iface, hold, uptime, srtt, rto, qcnt, seq = m.groups()
                # normalize Tu1 -> Tunnel1
                if iface.lower().startswith("tu"):
                    digits = re.sub(r"\D", "", iface)
                    iface = f"Tunnel{digits}" if digits else iface
                rows.append({
                    "address": addr, "iface": iface, "hold": hold, "uptime": uptime,
                    "srtt": srtt, "rto": rto, "qcnt": qcnt, "seq": seq
                })
        return rows


    # ------------ PAINTERS (force repaint on GUI thread) ------------
    def _fill_dmvpn_table(self, rows: list):
        # Bounce to GUI thread if needed
        if QtCore.QThread.currentThread() != QtWidgets.QApplication.instance().thread():
            QtCore.QMetaObject.invokeMethod(
                self, "_fill_dmvpn_table", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(list, rows)
            ); return

        tbl = self.dmvpnTable  # created in _setup_tunnels_tab
        tbl.setSortingEnabled(False)
        tbl.clearContents()
        tbl.setRowCount(len(rows))

        for r, d in enumerate(rows):
            tbl.setItem(r, 0, QtWidgets.QTableWidgetItem(d.get("tunnel","")))
            tbl.setItem(r, 1, QtWidgets.QTableWidgetItem(d.get("peer","")))
            tbl.setItem(r, 2, QtWidgets.QTableWidgetItem(d.get("nbma","")))
            st = d.get("state","").lower()
            st_txt = "UP" if st == "up" else ("DOWN" if st == "down" else st.upper())
            item_state = QtWidgets.QTableWidgetItem(st_txt)
            if st == "up":
                item_state.setForeground(QtGui.QBrush(QtGui.QColor("#10b981")))  # green
            elif st == "down":
                item_state.setForeground(QtGui.QBrush(QtGui.QColor("#ef4444")))  # red
            tbl.setItem(r, 3, item_state)
            tbl.setItem(r, 4, QtWidgets.QTableWidgetItem(d.get("note","")))

        tbl.resizeColumnsToContents()
        tbl.horizontalHeader().setStretchLastSection(True)
        tbl.viewport().update()
        tbl.setSortingEnabled(True)
        print("DMVPN rowCount:", tbl.rowCount())


    def _fill_eigrp_table(self, rows: list):
        # Bounce to GUI thread if needed
        if QtCore.QThread.currentThread() != QtWidgets.QApplication.instance().thread():
            QtCore.QMetaObject.invokeMethod(
                self, "_fill_eigrp_table", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(list, rows)
            ); return

        tbl = self.eigrpTable
        tbl.setSortingEnabled(False)
        tbl.clearContents()
        tbl.setRowCount(len(rows))

        for r, d in enumerate(rows):
            tbl.setItem(r, 0, QtWidgets.QTableWidgetItem(d.get("addr","")))
            tbl.setItem(r, 1, QtWidgets.QTableWidgetItem(d.get("iface","")))
            tbl.setItem(r, 2, QtWidgets.QTableWidgetItem(d.get("hold","")))
            tbl.setItem(r, 3, QtWidgets.QTableWidgetItem(d.get("uptime","")))
            tbl.setItem(r, 4, QtWidgets.QTableWidgetItem(d.get("srtt","")))
            tbl.setItem(r, 5, QtWidgets.QTableWidgetItem(d.get("rto","")))
            tbl.setItem(r, 6, QtWidgets.QTableWidgetItem(d.get("seq","")))

        tbl.resizeColumnsToContents()
        tbl.horizontalHeader().setStretchLastSection(True)
        tbl.viewport().update()
        tbl.setSortingEnabled(True)
        print("EIGRP rowCount:", tbl.rowCount())

    def _auto_detect_and_flag_hub(self, row_index: int, dev: dict):
        if not ALLOW_SSH_HUB_DETECT:
            return
        ip = dev.get("ip")
        if not ip or ip in self._autohub_checked or dev.get("is_hub", False):
            return
        # NEW: only probe known hubs
        if ip not in HUB_PROBE_ALLOWLIST:
            return

        self._autohub_checked.add(ip)

        def task():
            try:
                ok, reason, facts = detect_dmvpn_hub_over_ssh(ip)
                print(f"[HUB-AUTO] {ip} -> ok={ok} reason={reason} facts={facts}")
                if ok:
                    set_device_hub_flag(dev["id"], True)
                    QtCore.QTimer.singleShot(0, self.refresh_devices_from_db)
            except Exception as e:
                print(f"[HUB-AUTO] {ip} thread error: {e}")
        threading.Thread(target=task, daemon=True).start()

    def _find_device_by_id(self, dev_id: int):
        return next((d for d in self.devices if d.get("id") == dev_id), None)

    def open_settings_dialog_by_id(self, dev_id: int):
        dev = self._find_device_by_id(dev_id)
        if not dev:
            QtWidgets.QMessageBox.warning(self, "Not found", "Device not found.")
            return

        dlg = DeviceSettingsDialog(device=dev, parent=self)
        dlg.device_id = dev.get("id")  # ensure present

        if dlg.exec_() != QtWidgets.QDialog.Accepted:
            return

        updated = dlg.get_data()
        updated.setdefault("id", dev["id"])
        try:
            update_device_in_db(updated)   # writes devices + device_cellular
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Save failed", str(e))
            return

        # Repaint the affected row so user sees new SIM/IDs immediately
        self.refresh_devices_from_db()  # simplest
        # (or do a light repaint of SIM/APN/ICCID columns if you prefer)

    # Inside class CiscoSMSMonitorApp

    def register_device_by_id(self, dev_id: int):
        idx = next((i for i, dv in enumerate(self.devices) if dv.get("id") == dev_id), None)
        if idx is None:
            QtWidgets.QMessageBox.warning(self, "Not found", "Device row not found.")
            return
        self.device_register(idx)
        try:
            ip = self.devices[idx]["ip"]
            _REGISTER_CACHE.pop(ip, None)  # flip status quickly
        except Exception:
            pass
        self.refresh_devices_from_db()

    def add_device(self):
        """Open the Add Device dialog, insert to DB, and refresh UI."""
        dialog = DeviceSettingsDialog(parent=self)
        if dialog.exec_() != QtWidgets.QDialog.Accepted:
            return

        new_device = dialog.get_data()
        self.spinner.start()

        def background_task():
            try:
                # Save to DB
                insert_device_to_db(new_device)

                # If the device has cellular, configure the EEM applet for SMS extraction
                try:
                    if list_cellular_interfaces(new_device.get("ip", "")):
                        username, password = get_ssh_credentials()
                        if username and password:
                            configure_sms_applet_on_cisco(new_device["ip"], username, password)
                except Exception as sub_e:
                    # Non-fatal; just log
                    print(f"⏭️ Skipping/failed EEM config for {new_device.get('ip','?')}: {sub_e}")

                # Reload devices and push back to UI thread
                updated_devices = load_devices_from_db()
                self.worker_signals.deviceAdded.emit(updated_devices)

            except Exception as e:
                QtCore.QTimer.singleShot(
                    0,
                    lambda: QtWidgets.QMessageBox.warning(
                        self, "Error", f"Failed to add device:\n{e}"
                    ),
                )

        threading.Thread(target=background_task, daemon=True).start()

    def delete_device_by_id(self, dev_id: int):
        device = self._find_device_by_id(dev_id)
        if not device:
            QtWidgets.QMessageBox.warning(self, "Not found", "Device could not be found.")
            return
        name = device.get("name", "Unknown")
        if QtWidgets.QMessageBox.question(
            self, "Confirm Deletion", f"Delete device '{name}'?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
        ) == QtWidgets.QMessageBox.Yes:
            try:
                delete_device_from_db(device["id"])
                self.refresh_devices_from_db()
                QtWidgets.QMessageBox.information(self, "Deleted", f"Device '{name}' was deleted.")
            except Exception as e:
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to delete device:\n{e}")

    def show_sms_log_dialog_by_id(self, dev_id: int):
        device = self._find_device_by_id(dev_id)
        if not device:
            QtWidgets.QMessageBox.warning(self, "Not found", "Device could not be found.")
            return
        if not device.get("has_cellular", False):
            QtWidgets.QMessageBox.information(self, "No Cellular", "This device has no cellular interface.")
            return

        self.spinner.start()
        name, ip = device["name"], device["ip"]

        def task():
            try:
                logs_text = get_all_sms(ip)                      # returns raw string
                logs_list = parse_sms_view_all_for_dialog(logs_text)  # ← normalize shape
                self.worker_signals.smsLogsFetched.emit(name, logs_list)
            except Exception as e:
                QTimer.singleShot(0, lambda: QtWidgets.QMessageBox.critical(self, "Error", str(e)))
                self.worker_signals.smsLogsFetched.emit(name, [])
        threading.Thread(target=task, daemon=True).start()

    # --- helpers: find device & row by IP ---------------------------------------
    def _find_device_by_ip(self, ip: str):
        """Return the device dict with matching IP from in-memory lists."""
        ip = (ip or "").strip()
        # primary source
        for d in getattr(self, "devices", []):
            if (d.get("ip") or "").strip() == ip:
                return d
        # what’s currently shown (after filters/sorts)
        for d in getattr(self, "_view_devices", []):
            if (d.get("ip") or "").strip() == ip:
                return d
        return None
    
    def _col_index_e(self, header_text: str, default: int = -1) -> int:
        """Return the column index for a header (case-insensitive), or default."""
        try:
            for c in range(self.deviceTable.columnCount()):
                item = self.deviceTable.horizontalHeaderItem(c)
                if item and item.text().strip().lower() == header_text.strip().lower():
                    return c
        except Exception:
            pass
        return default

    def _find_row_by_ip(self, ip: str):
        """Return the QTableWidget row index for the device with this IP."""
        ip = (ip or "").strip()
        col_ip = self._col_index_e("IP") if hasattr(self, "_col_index_e") else -1
        if col_ip == -1:
            # fallback: linear scan of every column to look for a matching IP string
            rows = self.deviceTable.rowCount()
            cols = self.deviceTable.columnCount()
            for r in range(rows):
                for c in range(cols):
                    it = self.deviceTable.item(r, c)
                    if it and it.text().strip() == ip:
                        return r
            return None
        # fast path: check just the IP column
        rows = self.deviceTable.rowCount()
        for r in range(rows):
            it = self.deviceTable.item(r, col_ip)
            if it and it.text().strip() == ip:
                return r
        return None

    def _get_column_index(self, header_text: str):
        if not hasattr(self, "deviceTable") or self.deviceTable is None:
            return None
        wanted = (header_text or "").strip().lower()
        for i in range(self.deviceTable.columnCount()):
            hdr = self.deviceTable.horizontalHeaderItem(i)
            if hdr and hdr.text().strip().lower() == wanted:
                return i
        return None

    def _ensure_on_gui(self, fn, *args, **kwargs):
        """
        Run `fn` on the GUI thread (useful when called from worker threads).
        """
        app_thread = QtWidgets.QApplication.instance().thread()
        if QtCore.QThread.currentThread() is not app_thread:
            QtCore.QTimer.singleShot(0, lambda: fn(*args, **kwargs))
            return False
        return True


    def show_send_sms_dialog_by_id(self, dev_id: int):
        device = self._find_device_by_id(dev_id)
        if not device:
            QtWidgets.QMessageBox.warning(self, "Not found", "Device could not be found.")
            return
        if not device.get("has_cellular", False):
            QtWidgets.QMessageBox.information(self, "No Cellular",
                                            f"'{device.get('name','Unknown')}' has no cellular interface.")
            return

        dialog = SendSMSDialog(device_name=device["name"], router_ip=device["ip"], parent=self)

        # Optional convenience: prefill with the device’s own SIM if present
        sim_val = (device.get("sim") or "").strip()
        if sim_val:
            dialog.to_input.setText(sim_val)

        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            to_text, message = dialog.get_sms_data()
            recipient = self._resolve_recipient(to_text)
            if not recipient:
                QtWidgets.QMessageBox.warning(
                    self, "Unknown recipient",
                    "Enter a phone number, or a device name that has a SIM set."
                )
                return
            username, password = get_ssh_credentials()
            self.send_sms(device["ip"], username, password, recipient, message)

            # ✅ No SIM check here anymore
            dialog = SendSMSDialog(device_name=device["name"], router_ip=device["ip"], parent=self)

            # Optional: prefill the To: field if we *do* have a SIM value
            sim_val = (device.get("sim") or "").strip()
            if sim_val:
                dialog.to_input.setText(sim_val)

            # if dialog.exec_() == QtWidgets.QDialog.Accepted:
            #     to_number, message = dialog.get_sms_data()
            #     if not to_number.strip():
            #         QtWidgets.QMessageBox.warning(self, "Missing number", "Please enter a recipient number.")
            #         return
            #     username, password = get_ssh_credentials()
            #     self.send_sms(device["ip"], username, password, to_number.strip(), message)

    # ---------- Inbox table fetch/render ----------
    def _populate_inbox_table(self, smsList):
        if not self.smsInboxTable:
            return
        self.smsInboxTable.setColumnCount(4)
        self.smsInboxTable.setColumnWidth(0, 150)
        self.smsInboxTable.setColumnWidth(1, 150)
        self.smsInboxTable.setColumnWidth(2, 150)
        self.smsInboxTable.setColumnWidth(3, 350)
        self.smsInboxTable.setHorizontalHeaderLabels(["Device", "Message Receive", "Message From", "Message Content"])
        self.smsInboxTable.setRowCount(len(smsList))
        for i, d in enumerate(smsList):
            self.smsInboxTable.setItem(i, 0, QtWidgets.QTableWidgetItem(str(d[0] or "")))
            self.smsInboxTable.setItem(i, 1, QtWidgets.QTableWidgetItem(str(d[1] or "")))
            self.smsInboxTable.setItem(i, 2, QtWidgets.QTableWidgetItem(str(d[2] or "")))
            self.smsInboxTable.setItem(i, 3, QtWidgets.QTableWidgetItem(str(d[3] or "")))
        if self.inboxSearchLineEdit:
            self.filter_inbox_table(self.inboxSearchLineEdit.text())

    def fetch_all_devices(self):
        def task():
            devices = load_devices_from_db()
            smsList = fetch_from_all_devices(devices)
            QtCore.QTimer.singleShot(0, lambda lst=smsList: self._populate_inbox_table(lst))
        threading.Thread(target=task, daemon=True).start()

    def filter_inbox_table(self, text=None):
        if not self.smsInboxTable:
            return
        q = (text if text is not None else (self.inboxSearchLineEdit.text() if self.inboxSearchLineEdit else "")).strip().lower()
        rows = self.smsInboxTable.rowCount()
        for r in range(rows):
            device  = (self.smsInboxTable.item(r, 0).text() if self.smsInboxTable.item(r, 0) else "").lower()
            dates   = (self.smsInboxTable.item(r, 1).text() if self.smsInboxTable.item(r, 1) else "").lower()
            sender  = (self.smsInboxTable.item(r, 2).text() if self.smsInboxTable.item(r, 2) else "").lower()
            message = (self.smsInboxTable.item(r, 3).text() if self.smsInboxTable.item(r, 3) else "").lower()
            match = (q in device) or (q in dates) or (q in sender) or (q in message)
            self.smsInboxTable.setRowHidden(r, not match)

    # ---------- Window housekeeping ----------
    def _resizeEvent(self, event):
        self.spinner.setGeometry(self.rect())
        super().resizeEvent(event)

    def _toggle_sort_order(self):
        self.sortOrderButton.setText("Desc" if self.sortOrderButton.isChecked() else "Asc")
        self.apply_filters_and_sort()

    # ---------- Device filtering/sorting ----------
    def filter_devices(self):
        self.apply_filters_and_sort()

    def apply_filters_and_sort(self):
        devices = list(self.devices)

        qwidget = self.deviceSearchLineEdit
        query = (qwidget.text() if qwidget else "").lower().strip()
        if query:
            devices = [d for d in devices if
                       query in d["name"].lower() or
                       query in d["ip"] or
                       query in (d.get("sim") or "")]

        status_sel = self.statusFilterCombo.currentText()
        if status_sel in ("Online", "Offline"):
            devices = [d for d in devices if d["status"] == status_sel]

        if self.simOnlyCheck.isChecked():
            devices = [d for d in devices if (d.get("sim") or "").strip()]

        if self.hubsOnlyCheck.isChecked():
            devices = [d for d in devices if d.get("is_hub")]

        sort_map = {"Device": 0, "IP": 1, "Gateway": 2, "Status": 8}
        sort_label = self.sortByCombo.currentText()
        sort_col = sort_map.get(sort_label, 0)

        header = self.deviceTable.horizontalHeader()
        cur_sort_col = header.sortIndicatorSection()
        cur_sort_order = header.sortIndicatorOrder()

        self.load_devices(devices)

        if sort_col is not None:
            order = Qt.AscendingOrder if not self.sortOrderButton.isChecked() else Qt.DescendingOrder
            self.deviceTable.sortItems(sort_col, order)
        else:
            self.deviceTable.sortItems(cur_sort_col, cur_sort_order)

    def get_router_name(self, ip):
        for device in self.devices:
            if device["ip"] == ip:
                return device["name"]
        return ip

    # ---------- Device actions ----------
    def open_db_settings(self):
        DBSettingsDialog(self).exec_()

    def open_email_settings_dialog(self):
        EmailSettingsDialog(self).exec_()

    def open_email_notification(self):
        EmailNotificationDialog(self).show()

    def open_ssh_credentials_dialog(self):
        SSHCredentialsDialog(self).exec_()

    def refresh_devices_from_db(self):
        self._autohub_checked.clear()
        self.spinner.start()
        def refresh_task():
            try:
                devices = load_devices_from_db()
                self.worker_signals.refreshCompleted.emit(devices)
            except Exception as e:
                QTimer.singleShot(0, lambda: QtWidgets.QMessageBox.critical(self, "Error", f"Refresh failed: {e}"))
                QTimer.singleShot(0, self.spinner.stop)
        threading.Thread(target=refresh_task, daemon=True).start()

    @pyqtSlot(list)
    def update_devices_after_refresh(self, devices):
        self.devices = devices
        self.apply_filters_and_sort()
        self.spinner.stop()

    # Add to class CiscoSMSMonitorApp
    @pyqtSlot(list)
    def update_devices_and_ui(self, updated_devices):
        """Handle deviceAdded signal after Add Device completes."""
        self.spinner.stop()
        self.devices = updated_devices
        self.apply_filters_and_sort()

    # ---------- Device register (syslog host) ----------
    def device_register(self, index):
        ip = self.devices[index]["ip"]
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        username, password = get_ssh_credentials()
        ssh.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False)
        shell = ssh.invoke_shell()
        commands = ["conf t", f"logging host {get_ip_address()}", "end", "write memory"]
        for cmd in commands:
            shell.send(cmd + "\n"); time.sleep(0.8)
        time.sleep(1.5)
        _ = shell.recv(5000).decode()
        ssh.close()
        self.devices = load_devices_from_db()
        self.load_devices(self.devices)
        QtWidgets.QMessageBox.information(self, "Registered",
            f"Syslog host set on {self.devices[index]['name']} ({self.devices[index]['ip']}).")

    # --- add inside CiscoSMSMonitorApp ---
    def _clear_cell(self, row: int, col: int):
        """Remove any cell widget and clear the item so we can safely replace."""
        w = self.deviceTable.cellWidget(row, col)
        if w:
            try:
                self.deviceTable.removeCellWidget(row, col)
                w.deleteLater()
            except Exception:
                pass
        # also clear any existing item
        self.deviceTable.setItem(row, col, QtWidgets.QTableWidgetItem(""))

    def _set_sim_apn_cells(self, row: int, has_cell: bool, sim_text: str, apn_text: str):
        SIM_COL, APN_COL = 3, 4
        # always clear first so we can switch between widget<->item cleanly
        self._clear_cell(row, SIM_COL)
        self._clear_cell(row, APN_COL)
        if not has_cell:
            self.deviceTable.setCellWidget(row, SIM_COL, badge_widget("NO CELL"))
            self.deviceTable.setCellWidget(row, APN_COL, badge_widget("NO CELL"))
        else:
            self.deviceTable.setItem(row, SIM_COL, QtWidgets.QTableWidgetItem(sim_text or ""))
            self.deviceTable.setItem(row, APN_COL, QtWidgets.QTableWidgetItem(apn_text or ""))

    def _send_sms_to(self, dev_id: int, to_number: str):
        # If your dialog supports prefill, add this overload:
        try:
            # Preferred: extend your method signature to accept default_to
            self.show_send_sms_dialog_by_id(dev_id, default_to=to_number)
            return
        except TypeError:
            pass
        # Fallback: open the normal dialog (user types number there)
        self.show_send_sms_dialog_by_id(dev_id)

    # ---------- Table build ----------
    def load_devices(self, device_list):
        # stop and clear any previous per-row timers
        for _t in getattr(self, "_sms_pending", {}).values():
            try: _t.stop()
            except: pass
        self._sms_pending = {}

        print(f"🔄 Loading {len(device_list)} devices into table")
        self._view_devices = list(device_list)

        self.deviceTable.setSortingEnabled(False)

        # ⬅️ We now have 11 columns (added ICCID after APN)
        self.deviceTable.setColumnCount(11)
        self.deviceTable.setHorizontalHeaderLabels([
            "Device", "IP", "Gateway", "SIM", "APN",
            "ICCID",                      # new column
            "Email", "Last SMS", "Signal", "Status", "Actions"
        ])
        self.deviceTable.setRowCount(len(device_list))
        self.deviceTable.setItemDelegateForColumn(0, DeviceDelegate(self.deviceTable))
        
        self.simDelegate = SimDelegate(self.deviceTable)
        self.deviceTable.setItemDelegateForColumn(3, self.simDelegate)  # SIM column
        self.simDelegate.sendSmsRequested.connect(self._send_sms_to)
        
        self.apnDelegate = ApnDelegate(self.deviceTable)
        self.deviceTable.setItemDelegateForColumn(4, self.apnDelegate)

        self.deviceTable.setWordWrap(False)
        fm = self.deviceTable.fontMetrics()
        self.deviceTable.verticalHeader().setDefaultSectionSize(fm.height() + 12)
        self.deviceTable.horizontalHeader().setSectionsClickable(True)

        # resolve Last SMS column index once (fallback moved from 6 → 7 because of ICCID)
        self._last_sms_col = _col_index(self, "Last SMS", default=7)

        for i, d in enumerate(device_list):
            dev_id = d["id"]

            if d["status"] == "Online" and not d.get("is_hub", False):
                self._auto_detect_and_flag_hub(i, d)

            # columns 0..2
            item0 = QtWidgets.QTableWidgetItem(d["name"])
            item0.setFlags(item0.flags() & ~QtCore.Qt.ItemIsEditable)
            item0.setData(DEVICE_HUB_ROLE, 1 if d.get("is_hub", False) else 0)
            self.deviceTable.setItem(i, 0, item0)
            self.deviceTable.setItem(i, 1, IPItem(d["ip"]))
            self.deviceTable.setItem(i, 2, QtWidgets.QTableWidgetItem(d["gateway"]))

            # SIM (col 3)
            sim_txt = (d.get("sim") or "").strip()
            it_sim = QtWidgets.QTableWidgetItem(sim_txt)
            it_sim.setFlags(it_sim.flags() & ~QtCore.Qt.ItemIsEditable)
            it_sim.setData(SIM_TEXT_ROLE, sim_txt)
            it_sim.setData(DEVICE_ID_ROLE, int(d["id"]))
            self.deviceTable.setItem(i, 3, it_sim)

            # APN (col 4)
            apn_txt = (d.get("apn") or "").strip()
            it_apn = QtWidgets.QTableWidgetItem(apn_txt)
            it_apn.setFlags(it_apn.flags() & ~QtCore.Qt.ItemIsEditable)
            it_apn.setData(APN_TEXT_ROLE, apn_txt)
            self.deviceTable.setItem(i, 4, it_apn)

            # ICCID (col 5) — show parsed ICCID from best cellular iface (or em dash)
            col_iccid = _col_index(self, "ICCID")     # <-- use function, not self._col_index
            if col_iccid != -1:
                iccid_txt = d.get("iccid") or "—"
                item = QtWidgets.QTableWidgetItem(iccid_txt)
                item.setTextAlignment(Qt.AlignCenter)
                self.deviceTable.setItem(i, col_iccid, item)

            # Email (shifted to col 6)
            self.deviceTable.setItem(i, 6, QtWidgets.QTableWidgetItem(d["email"]))

            # Last SMS: spinner + watchdog if cellular, else static text
            if d.get("has_cellular", False):
                self._start_row_fetch(i, d["ip"])
            else:
                last_col = self._last_sms_col
                w = self.deviceTable.cellWidget(i, last_col)
                if w:
                    mv = getattr(w, "movie", None)
                    if mv: mv.stop()
                    self.deviceTable.removeCellWidget(i, last_col)
                    w.deleteLater()
                self.deviceTable.setItem(i, last_col, QtWidgets.QTableWidgetItem("No Cellular"))

            # Signal (shifted to col 8)
            self.deviceTable.setItem(i, 8, QtWidgets.QTableWidgetItem("▓" * d.get("signal", 0)))

            # Status (shifted to col 9)
            status_widget = create_status_label(d["status"])
            self.deviceTable.setCellWidget(i, 9, status_widget)

            # Actions menu (shifted to col 10)
            action_button = QToolButton()
            action_button.setText("Edit")
            action_button.setIcon(QIcon(resource_path("icons/edit.png")))
            action_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
            action_button.setPopupMode(QToolButton.MenuButtonPopup)
            menu = QMenu(action_button)

            actDetectAll = QtWidgets.QAction("Detect All (Gateway → Cellular → APN)", self)
            actDetectAll.setIcon(QIcon(resource_path("icons/scan.png")))
            menu.insertAction(menu.actions()[0] if menu.actions() else None, actDetectAll)
            current_id = d["id"]
            actDetectAll.triggered.connect(
                lambda checked=False, dev_id=current_id: self.detect_all_from_row(dev_id)
            )

            need_register = d.get("has_cellular", False) and d.get("status") == "Not Register"

            detect_hub_action = QAction("Detect hub now", self)
            menu.addAction(detect_hub_action); menu.addSeparator()

            toggle_hub_action = QAction("Mark as Hub" if not d.get("is_hub") else "Mark as Spoke", self)
            menu.addAction(toggle_hub_action); menu.addSeparator()

            sms_logs_action = QAction(QIcon(resource_path("icons/sms.png")), "SMS Logs", self)
            send_sms_action = QAction(QIcon(resource_path("icons/send.png")), "Send SMS", self)
            delete_action   = QAction(QIcon(resource_path("icons/delete.png")), "Delete", self)

            has_cell = bool(d.get("has_cellular"))
            if not has_cell:
                sms_logs_action.setEnabled(False)
                sms_logs_action.setStatusTip("No cellular interface on this device")
            menu.addAction(sms_logs_action)

            # allow Send SMS whenever the device has cellular
            can_send = has_cell
            send_sms_action.setEnabled(can_send)
            if not has_cell:
                send_sms_action.setStatusTip("Send SMS disabled: no cellular interface")
            menu.addAction(send_sms_action)

            menu.addSeparator()
            menu.addAction(delete_action)

            action_button.setMenu(menu)
            self.deviceTable.setCellWidget(i, 10, action_button)

            # Connect actions
            action_button.clicked.connect(lambda _, id=dev_id: self.open_settings_dialog_by_id(id))
            sms_logs_action.triggered.connect(lambda _, id=dev_id: self.show_sms_log_dialog_by_id(id))
            send_sms_action.triggered.connect(lambda _, id=dev_id: self.show_send_sms_dialog_by_id(id))
            delete_action.triggered.connect(lambda _, id=dev_id: self.delete_device_by_id(id))

            if need_register:
                register_action = QAction(QIcon(resource_path("icons/plug.png")), "Register (set logging host)", self)
                register_action.setStatusTip("Configure this router to send syslog to this app")
                register_action.triggered.connect(lambda _, id=dev_id: self.register_device_by_id(id))
                menu.addAction(register_action)
                menu.addSeparator()

            def on_toggle_hub(id=dev_id):
                try:
                    dev = self._find_device_by_id(id)
                    set_device_hub_flag(dev["id"], not dev.get("is_hub", False))
                    self.refresh_devices_from_db()
                except Exception as e:
                    QtWidgets.QMessageBox.critical(self, "Error", f"Failed to update Hub flag:\n{e}")
            toggle_hub_action.triggered.connect(on_toggle_hub)

            def on_detect_hub_now(id=dev_id):
                dev = self._find_device_by_id(id)
                ip  = dev["ip"]
                try:
                    ok, reason, facts = detect_dmvpn_hub_over_ssh(ip)
                    if ok and not dev.get("is_hub", False):
                        set_device_hub_flag(dev["id"], True)
                        QtWidgets.QMessageBox.information(self, "Hub detected",
                                                        f"{dev['name']} marked as HUB\n{reason}")
                        self.refresh_devices_from_db()
                    else:
                        QtWidgets.QMessageBox.information(self, "Detection",
                            f"Detector says: {'HUB' if ok else 'Not a hub'}\n{reason}")
                except Exception as e:
                    QtWidgets.QMessageBox.critical(self, "Detect failed", str(e))
            detect_hub_action.triggered.connect(on_detect_hub_now)

        self.deviceTable.setSortingEnabled(True)

    def detect_all_from_row(self, dev_id: int):
        dev = self._find_device_by_id(dev_id)
        if not dev:
            QtWidgets.QMessageBox.warning(self, "Not found", "Device could not be found.")
            return
        if not (dev.get("ip") or "").strip():
            QtWidgets.QMessageBox.warning(self, "Missing IP", "This device has no IP configured.")
            return

        # UI
        dlg = DetectAllProgress(self)
        runner = DetectAllRunner(dev)
        thr = QtCore.QThread(self)
        runner.moveToThread(thr)

        # signals
        runner.step_started.connect(dlg.show_step_started)
        def on_done(name, ok, payload):
            dlg.show_step_done(name, ok, payload)
            # refresh device table after each step so user sees incremental results
            self.refresh_devices_from_db()
        runner.step_done.connect(on_done)

        def on_finished():
            thr.quit(); thr.wait()
            dlg.l_status.setText("Finished.")
            # short delay so the user can see the last line update, then close
            QtCore.QTimer.singleShot(600, dlg.accept)

        runner.finished.connect(on_finished)
        dlg.btnCancel.clicked.connect(runner.cancel)

        thr.started.connect(runner.run)
        thr.start()
        dlg.exec_()  # modal progress while the worker runs

    def update_last_sms(self, row, ip):
        def work():
            sms = _extract_sms_body(fetch_last_sms(ip))
            self.sms_signal.smsFetched.emit(row, sms)
        self._sms_pool.submit(work)

    # ---------- Live SMS logs tab ----------
    @pyqtSlot(str, list)
    def display_sms_log_dialog_result(self, name, logs):
        self.spinner.stop()
        app_thread = QtWidgets.QApplication.instance().thread()
        if QtCore.QThread.currentThread() is not app_thread:
            QtCore.QTimer.singleShot(0, lambda: self.display_sms_log_dialog_result(name, logs))
            return

        # Now we're safely on the GUI thread:
        dialog = SMSLogDialog(device_name=name, sms_logs=logs, parent=self)
        dialog.exec_()  # OK now

    def filter_sms_logs(self):
        if not hasattr(self, "smsSearchLineEdit"):
            return
        keyword = self.smsSearchLineEdit.text().lower()
        filtered = [sms for sms in self.sms_logs
                    if keyword in sms.get("Content","").lower()
                    or keyword in sms.get("From","").lower()
                    or keyword in sms.get("Router","").lower()]
        self.display_sms_logs(filtered)

    def init_live_sms_tab(self):
        self.tabLiveSms = QtWidgets.QWidget()
        self.tabWidget.addTab(self.tabLiveSms, "Live SMS Capture")

        lay = QtWidgets.QVBoxLayout(self.tabLiveSms)

        # Search box (optional)
        self.searchSmsLogs = QtWidgets.QLineEdit()
        self.searchSmsLogs.setPlaceholderText("Search SMS logs")
        lay.addWidget(self.searchSmsLogs)

        # ✅ The table we will fill
        self.smsCaptureTable = QtWidgets.QTableWidget()
        self.smsCaptureTable.setAlternatingRowColors(True)
        self.smsCaptureTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.smsCaptureTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.smsCaptureTable.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        lay.addWidget(self.smsCaptureTable)

        # Bottom bar (status/export) — optional
        bottom = QtWidgets.QHBoxLayout()
        self.liveSmsStatus = QtWidgets.QLabel("Listening for SMS…")
        bottom.addWidget(self.liveSmsStatus, 1)
        self.btnExportSmsCsv = QtWidgets.QPushButton("Export to CSV")
        bottom.addWidget(self.btnExportSmsCsv, 0)
        lay.addLayout(bottom)

    def _ensure_sms_capture_table(self):
        return self.smsCaptureTable

    def display_sms_logs(self, logs):
        table = self._ensure_sms_capture_table()  # now guaranteed to be the .ui table

    def send_sms(self, router_ip, username, password, recipient, message):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(router_ip, username=username, password=password, look_for_keys=False, allow_agent=False)
            sms_iface = choose_sms_iface(router_ip)  # ← NEW
            cmd = f'{sms_iface} lte sms send {recipient} "{message}"'
            print(f"📤 Sending SMS: {cmd}")
            ssh.exec_command(cmd); ssh.close()
            QtWidgets.QMessageBox.information(self, "Success", f"SMS sent to {recipient}")
            lan_ip = map_to_lan(router_ip)  # 172.16.1.203 -> 192.168.203.1
            note_recent_sender(lan_ip)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Error", f"Failed to send SMS:\n{e}")

    @QtCore.pyqtSlot(object)
    def _add_sms_log_main_thread(self, sms):
        self.sms_logs.insert(0, sms)
        self.display_sms_logs(self.sms_logs[:100])

    def add_sms_log(self, sms):
        if QtCore.QThread.currentThread() is self.thread():
            self._add_sms_log_main_thread(sms); return
        QtCore.QMetaObject.invokeMethod(
            self, "_add_sms_log_main_thread",
            QtCore.Qt.QueuedConnection, QtCore.Q_ARG(object, sms)
        )

    @QtCore.pyqtSlot(object)
    def _display_sms_logs_main_thread(self, logs):
        table = self.smsCaptureTable  # <-- the one from .ui
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels(["Router","ID","Time","From","Size","Message"])
        table.setRowCount(len(logs))
        from datetime import datetime
        for i, sms in enumerate(logs):
            tstr = sms.get("Time") or sms.get("time") or ""
            try:
                tstr = datetime.strptime(tstr, "%y-%m-%d %H:%M:%S").strftime("%d/%m/%Y %H:%M:%S")
            except Exception:
                pass
            table.setItem(i, 0, QtWidgets.QTableWidgetItem(str(sms.get("Router","Unknown"))))
            table.setItem(i, 1, QtWidgets.QTableWidgetItem(str(sms.get("ID",""))))
            table.setItem(i, 2, QtWidgets.QTableWidgetItem(tstr))
            table.setItem(i, 3, QtWidgets.QTableWidgetItem(str(sms.get("From",""))))
            table.setItem(i, 4, QtWidgets.QTableWidgetItem(str(sms.get("Size",""))))
            table.setItem(i, 5, QtWidgets.QTableWidgetItem(sms.get("Content","")))
        table.resizeColumnsToContents()

    def display_sms_logs(self, logs):
        if QtCore.QThread.currentThread() is self.thread():
            self._display_sms_logs_main_thread(logs); return
        QtCore.QMetaObject.invokeMethod(
            self, "_display_sms_logs_main_thread",
            QtCore.Qt.QueuedConnection, QtCore.Q_ARG(object, logs)
        )

    def _refresh_device_by_ip(self, ip: str):
        """Re-pull cellular rows and repaint SIM/APN/ICCID for the device with this IP."""
        dev = self._find_device_by_ip(ip)
        if not dev:
            print(f"[refresh-by-ip] no device for {ip}")
            return

        dev_id = dev["id"]
        try:
            cells = get_device_cellular(dev_id) or []
        except Exception as e:
            print(f"[refresh-by-ip] get_device_cellular({dev_id}) failed: {e}")
            cells = []

        eligible = []
        for r in cells:
            row = {
                "interface": r.get("interface",""),
                "ip": r.get("ip_addr",""),
                "status": r.get("status",""),
                "protocol": r.get("protocol",""),
                "imsi": r.get("imsi",""),
                "imei": r.get("imei",""),
                "iccid": r.get("iccid",""),
                "apn": r.get("apn",""),
                "sim": r.get("sim") or "",
            }
            if _is_qualified_cell_row(row):
                eligible.append(row)

        best = max(eligible, key=_score_iface) if eligible else {}
        dev["has_cellular"] = bool(eligible)
        dev["sim"]   = best.get("sim","")
        dev["apn"]   = best.get("apn","")
        dev["iccid"] = best.get("iccid","")

        row_idx = self._find_row_by_ip(ip)
        if row_idx is None:
            print(f"[refresh-by-ip] UI row not found for {ip}")
            return

        # SIM + APN
        self._set_sim_apn_cells(row_idx, dev["has_cellular"], dev.get("sim",""), dev.get("apn",""))

        # ICCID
        col_iccid = self._col_index("ICCID")
        if col_iccid != -1:
            txt = dev.get("iccid") or "—"
            item = QtWidgets.QTableWidgetItem(txt)
            item.setTextAlignment(Qt.AlignCenter)
            self.deviceTable.setItem(row_idx, col_iccid, item)

        print(f"[refresh-by-ip] updated {ip}: sim='{dev['sim']}', apn='{dev['apn']}', iccid='{dev['iccid']}'")

    def _schedule_cell_refresh(self, delay_ms: int = 1000):
        if not hasattr(self, "_cell_refresh_timer"):
            self._cell_refresh_timer = QtCore.QTimer(self)
            self._cell_refresh_timer.setSingleShot(True)
            self._cell_refresh_timer.timeout.connect(self._refresh_dirty_devices)
            self._cell_dirty_ids = set()
        if not self._cell_refresh_timer.isActive():
            self._cell_refresh_timer.start(delay_ms)

    def _append_recent_sender(self, lan_ip: str):
        t = _now()
        self._recent_senders.append((lan_ip, t))
        # bound the list
        if len(self._recent_senders) > 200:
            self._recent_senders = self._recent_senders[-200:]

    def _pick_recent_sender(self) -> str | None:
        now = _clock()
        with self._senders_lock:
            for ip, t in reversed(self._recent_senders):
                # tolerate bad scales (ms / ns / strings)
                try:
                    ts = float(t)
                except Exception:
                    continue
                if ts > 1e12:      # looks like milliseconds
                    ts /= 1000.0
                if ts > 1e15:      # looks like nanoseconds
                    ts /= 1e9

                age = now - ts
                if 0 <= age <= RECENT_SENDER_WINDOW_SEC:
                    return ip
        # debug if nothing matched
        try:
            oldest = min((float(t) for _, t in self._recent_senders), default=None)
            newest = max((float(t) for _, t in self._recent_senders), default=None)
            print(f"[recent] none in window; count={len(self._recent_senders)}, "
                f"age_oldest={now-(oldest or now):.1f}s age_newest={now-(newest or now):.1f}s")
        except Exception:
            pass
        return None
    
    def _maybe_mark_refresh_by_ip(self, ip: str):
        dev = self._find_device_by_ip(ip)
        if not dev:
            return  # only devices that exist in DB
        if not hasattr(self, "_cell_dirty_ids"):
            self._cell_dirty_ids = set()
        self._cell_dirty_ids.add(dev["id"])
        self._schedule_cell_refresh()

    def _refresh_dirty_devices(self):
        ids = list(getattr(self, "_cell_dirty_ids", set()))
        self._cell_dirty_ids.clear()
        for dev_id in ids:
            dev = self._find_device_by_id(dev_id)
            if dev:
                self._refresh_device_by_ip(dev["ip"])

    def _map_syslog_ip_to_device_ip(self, syslog_ip: str) -> str:
        parts = (syslog_ip or "").split(".")
        if len(parts) == 4:
            # swap the last two octets: A.B.C.D -> 192.168.D.C
            return f"192.168.{parts[3]}.{parts[2]}"
        return 
    
    def _note_manual_sim_edit(self, device_id: int):
        self._last_manual_sim_edit[device_id] = _now()

    # ---------- Syslog listener ----------
    def start_syslog_listener(self):
        # --- Ring + lock for recent senders --------------------------------------
        from collections import deque
        import threading

        if not hasattr(self, "_recent_senders"):
            # store tuples (lan_ip, t)
            self._recent_senders = deque(maxlen=64)
        if not hasattr(self, "_recent_lock"):
            self._recent_lock = threading.Lock()

        # manual edit cool-down tracker (device_id -> timestamp)
        if not hasattr(self, "_last_manual_sim_edit"):
            self._last_manual_sim_edit = {}

        RECENT_SENDER_WINDOW_SEC = 180          # 3 minutes
        MANUAL_EDIT_COOLDOWN_SEC = 300          # 5 minutes

        def _now():
            import time
            return time.time()

        def is_phone_number(s: str) -> bool:
            return bool(re.fullmatch(r"[+]?[\d]{6,20}", (s or "").strip()))

        def normalize_msisdn(s: str) -> str:
            s = (s or "").strip()
            if s.startswith('+'):
                digits = '+' + ''.join(ch for ch in s[1:] if ch.isdigit())
            else:
                digits = ''.join(ch for ch in s if ch.isdigit())
            if digits.startswith('00') and len(digits) > 2:
                digits = '+' + digits[2:]
            return digits

        def pick_recent_sender() -> str | None:
            now = _now()
            with self._recent_lock:
                for ip, t in reversed(self._recent_senders):
                    if now - t <= RECENT_SENDER_WINDOW_SEC:
                        return ip
            return None

        def _note_recent_sender(lan_ip: str):
            with self._recent_lock:
                self._recent_senders.append((lan_ip, _now()))

        # --- DB write + repaint helpers (your versions kept & slightly hardened) --
        def update_sender_sim_in_db(device_id: int, sim_text: str, prefer_iface: str | None = None):
            db = mysql.connector.connect(**get_db_config())
            try:
                cur = db.cursor()
                row_id = None
                if prefer_iface:
                    cur.execute(
                        "SELECT id FROM device_cellular WHERE device_id=%s AND interface=%s LIMIT 1",
                        (device_id, prefer_iface),
                    )
                    r = cur.fetchone()
                    if r:
                        row_id = r[0]

                if row_id is None:
                    cur.execute(
                        """
                        SELECT id FROM device_cellular
                        WHERE device_id=%s
                        ORDER BY (ip_addr <> 'unassigned') DESC,
                                (status='up') DESC,
                                id DESC
                        LIMIT 1
                        """,
                        (device_id,),
                    )
                    r = cur.fetchone()
                    if r:
                        row_id = r[0]

                if row_id is not None:
                    cur.execute(
                        "UPDATE device_cellular SET sim=%s, last_seen=NOW() WHERE id=%s",
                        (sim_text, row_id),
                    )
                else:
                    cur.execute(
                        """
                        INSERT INTO device_cellular
                            (device_id, interface, ip_addr, status, protocol, sim, last_seen)
                        VALUES (%s, %s, %s, %s, %s, %s, NOW())
                        """,
                        (device_id, prefer_iface or "Cellular0/0/0", "unassigned", "down", "", sim_text),
                    )
                db.commit()
            finally:
                db.close()

        def repaint_sim_row(ip: str, sim_text: str):
            app_thr = QtWidgets.QApplication.instance().thread()
            if QtCore.QThread.currentThread() is not app_thr:
                QtCore.QTimer.singleShot(0, lambda: repaint_sim_row(ip, sim_text))
                return

            dev = self._find_device_by_ip(ip)
            if not dev:
                return

            sim_text = sim_text or ""
            dev["sim"] = sim_text
            if sim_text:
                dev["has_cellular"] = True

            # keep lists in sync
            for lst in (getattr(self, "devices", []), getattr(self, "_view_devices", [])):
                for d in lst or []:
                    if (d.get("ip") or "").strip() == ip:
                        d["sim"] = sim_text
                        if sim_text:
                            d["has_cellular"] = True

            row_idx = self._find_row_by_ip(ip)
            if row_idx is None:
                return

            apn_txt = dev.get("apn", "")
            if hasattr(self, "_set_sim_apn_cells"):
                self._set_sim_apn_cells(row_idx, dev.get("has_cellular", False), sim_text, apn_txt)
            else:
                col_idx = getattr(self, "_get_column_index", lambda _ : None)("SIM")
                if col_idx is not None and hasattr(self, "deviceTable"):
                    item = self.deviceTable.item(row_idx, col_idx)
                    if item is None:
                        item = QtWidgets.QTableWidgetItem()
                        self.deviceTable.setItem(row_idx, col_idx, item)
                    item.setText(sim_text)

            if hasattr(self, "deviceTable"):
                self.deviceTable.viewport().update()

        # -------------------------- main listener thread ---------------------------
        def listen():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 514))
            print("📡 Syslog listener started...")

            while True:
                data, addr = sock.recvfrom(8192)
                if self.is_paused:
                    continue

                msg = data.decode("utf-8", errors="ignore")
                nbma_ip = addr[0]  # e.g., 172.16.1.203

                # 1) OUTGOING sent: remember sender (LAN ip)
                if "%CELLWAN-5-OUTGOING_SMS_SENT" in msg:
                    sender_lan_ip = self._map_syslog_ip_to_device_ip(nbma_ip)
                    _note_recent_sender(sender_lan_ip)
                    # optional refresh of that row's last-sms cell
                    QtCore.QTimer.singleShot(
                        0, lambda ip=sender_lan_ip: self._maybe_mark_refresh_by_ip(ip)
                    )
                    continue

                # 2) Receiver extracted
                m = re.search(r"SMS Extracted\s*->\s*ID:\s*(\d+)", msg)
                if not m:
                    continue

                sms_index = m.group(1)

                # fetch the SMS from the receiver (use NBMA)
                try:
                    sms = fetch_sms_details(nbma_ip, sms_index)
                except Exception as e:
                    print(f"❌ fetch_sms_details failed for {nbma_ip}, ID {sms_index}: {e}")
                    continue

                # map receiver to LAN; ensure it's one of our devices
                receiver_lan_ip = self._map_syslog_ip_to_device_ip(nbma_ip)
                receiver_dev = self._find_device_by_ip(receiver_lan_ip)
                if not receiver_dev:
                    # Not an internal router -> do not autolearn
                    try:
                        self.add_sms_log(sms)  # still show in live pane if you like
                    except Exception:
                        pass
                    continue

                # tag + email (safe)
                try:
                    sms["Router"] = self.get_router_name(receiver_lan_ip)
                except Exception:
                    sms["Router"] = receiver_lan_ip
                try:
                    email_to = get_email_by_router_ip(receiver_lan_ip)
                    if email_to:
                        send_email(sms, email_to)
                except Exception as e:
                    print(f"❌ Email send failed: {e}")

                # Extract From and normalize
                try:
                    from_norm = normalize_msisdn(sms.get("From", ""))
                    if not is_phone_number(from_norm):
                        self.add_sms_log(sms)
                        continue

                    # pick most recent sender
                    sender_ip = pick_recent_sender()
                    if not sender_ip:
                        print("ℹ️ No recent sender to map this inbound 'From' number to.")
                        self.add_sms_log(sms)
                        continue

                    sender_dev = self._find_device_by_ip(sender_ip)
                    if not sender_dev or not sender_dev.get("id"):
                        self.add_sms_log(sms)
                        continue

                    # honor manual edit cool-down
                    last_manual = self._last_manual_sim_edit.get(sender_dev["id"], 0)
                    if last_manual and (_now() - last_manual) < MANUAL_EDIT_COOLDOWN_SEC:
                        print(f"ℹ️ Skipping autolearn for {sender_ip} (recent manual edit).")
                        self.add_sms_log(sms)
                        continue

                    current_norm = normalize_msisdn(sender_dev.get("sim", "")) or ""
                    if from_norm != current_norm:
                        try:
                            update_sender_sim_in_db(sender_dev["id"], from_norm)
                            sender_dev["sim"] = from_norm
                            QtCore.QTimer.singleShot(
                                0, lambda ip=sender_ip, s=from_norm: repaint_sim_row(ip, s)
                            )
                            print(f"✅ Learned SIM for {sender_ip}: {from_norm}")
                        except Exception as e:
                            print(f"⚠️ DB SIM update failed for {sender_ip}: {e}")

                    # finally log to live pane
                    self.add_sms_log(sms)

                except Exception as e:
                    print(f"⚠️ SIM learn failed (receiver {receiver_lan_ip}): {e}")
                    try:
                        self.add_sms_log(sms)
                    except Exception:
                        pass

        t = threading.Thread(target=listen, daemon=True)
        t.start()

    # ---------- Misc ----------
    def toggle_pause(self):
        self.is_paused = not self.is_paused
        self.pauseButton.setText("Resume" if self.is_paused else "Pause")
        self.statusLabel.setText("⏸️ Paused" if self.is_paused else "🟢 Listening for SMS...")

    def export_to_csv(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export SMS Logs", "", "CSV Files (*.csv)")
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            f.write("ID,Time,From,Size,Message\n")
            for log in self.sms_logs:
                content = log.get('Content','').replace('"', '""')
                f.write(f'{log.get("ID","")},{log.get("Time","")},{log.get("From","")},{log.get("Size","")},"{content}"\n')
        QtWidgets.QMessageBox.information(self, "Export", "SMS logs exported successfully.")

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

        if not text:          # show the same pill as SIM's empty
            paint_pill(painter, r, "NO CELL", opt.font)
        else:                  # normal APN text
            color = opt.palette.color(
                QtGui.QPalette.HighlightedText if (opt.state & QtWidgets.QStyle.State_Selected)
                else QtGui.QPalette.Text
            )
            painter.setPen(color)
            painter.drawText(r, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, text)

        painter.restore()

    def sizeHint(self, option, index):
        return super().sizeHint(option, index)

DEVICE_ID_ROLE = QtCore.Qt.UserRole + 200
SIM_TEXT_ROLE  = QtCore.Qt.UserRole + 201

class SimDelegate(QtWidgets.QStyledItemDelegate):
    sendSmsRequested = QtCore.pyqtSignal(int, str)  # (device_id, to_number)

    def __init__(self, parent=None):
        super().__init__(parent)
        # cache icon pixmap
        self.icon = QtGui.QIcon(resource_path("icons/send.png"))
        self._last_icon_rect = {}

    def paint(self, painter, option, index):
        opt = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        style = opt.widget.style() if opt.widget else QtWidgets.QApplication.style()
        style.drawPrimitive(QtWidgets.QStyle.PE_PanelItemViewItem, opt, painter, opt.widget)

        painter.save()
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        painter.setFont(opt.font)

        text = (index.data(SIM_TEXT_ROLE) or "").strip()
        r = opt.rect.adjusted(8, 0, -8, 0)  # padding

        if not text:
            paint_pill(painter, r, "NO CELL", opt.font)
            self._last_icon_rect[index] = QtCore.QRect()
            painter.restore()
            return
        else:
            # draw SIM text and a send icon at the right
            fm = QtGui.QFontMetrics(opt.font)
            icon_sz = min(max(fm.height(), 16), 20)
            icon_rect = QtCore.QRect(r.right()-icon_sz, r.top() + (r.height()-icon_sz)//2,
                                     icon_sz, icon_sz)
            text_rect = QtCore.QRect(r.left(), r.top(), icon_rect.left()-8 - r.left(), r.height())

            painter.setPen(opt.palette.color(
                QtGui.QPalette.HighlightedText if (opt.state & QtWidgets.QStyle.State_Selected)
                else QtGui.QPalette.Text
            ))
            painter.drawText(text_rect, QtCore.Qt.AlignVCenter | QtCore.Qt.AlignLeft, text)

            pm = self.icon.pixmap(icon_sz, icon_sz)
            style.drawItemPixmap(painter, icon_rect, QtCore.Qt.AlignCenter, pm)

            # remember clickable area for editorEvent
            self._last_icon_rect[index] = icon_rect

        painter.restore()

    def editorEvent(self, event, model, option, index):
        # click on icon → emit signal
        if event.type() == QtCore.QEvent.MouseButtonRelease and event.button() == QtCore.Qt.LeftButton:
            icon_rect = self._last_icon_rect.get(index, QtCore.QRect())
            if icon_rect.contains(event.pos()):
                dev_id = int(index.data(DEVICE_ID_ROLE) or 0)
                sim_to = (index.data(SIM_TEXT_ROLE) or "").strip()
                if dev_id and sim_to:
                    self.sendSmsRequested.emit(dev_id, sim_to)
                return True
        return super().editorEvent(event, model, option, index)

# Simple dialog for sending SMS
class SendSMSDialog(QtWidgets.QDialog):
    def __init__(self, device_name, router_ip, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Send SMS via {device_name}")
        self.setFixedSize(300, 200)
        layout = QVBoxLayout()
        self.to_input = QtWidgets.QLineEdit(); self.to_input.setPlaceholderText("Recipient Number")
        layout.addWidget(QtWidgets.QLabel("To:")); layout.addWidget(self.to_input)
        self.message_input = QtWidgets.QPlainTextEdit(); self.message_input.setPlaceholderText("Enter your message")
        layout.addWidget(QtWidgets.QLabel("Message:")); layout.addWidget(self.message_input)
        send_btn = QPushButton("Send"); send_btn.clicked.connect(self.accept)
        layout.addWidget(send_btn)
        self.setLayout(layout)
        self.router_ip = router_ip
    def get_sms_data(self):
        return self.to_input.text(), self.message_input.toPlainText()

# ---------- get email by router ip ----------
def get_email_by_router_ip(router_ip):
    db_config = get_db_config()
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("""SELECT email FROM devices WHERE ip = %s""", (router_ip,))
    result = cursor.fetchone()
    cursor.close(); conn.close()
    return result[0] if result else None

# ---------- App entry ----------
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