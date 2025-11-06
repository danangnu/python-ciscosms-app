#!/usr/bin/env python3
"""
collect_router_firmware.py

SSH to a range of routers, run 'show version' (and a few other probes),
parse UNIVERSALK9 image and Version, try to pick up cellular/modem firmware,
and save results to XLSX/CSV.

Dependencies:
    pip install paramiko pandas openpyxl

Usage:
    - Edit the CONFIG section below (or pass via env vars in future).
    - Prepare network reachability (can SSH to each host).
    - Run: python collect_router_firmware.py
"""

import re
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import pandas as pd
import paramiko

# -----------------------------
# CONFIG
# -----------------------------
USERNAME = "admin"
PASSWORD = "Bryan2011"
# subnet template: change if not 192.168
SUBNET_TEMPLATE = "192.168.{x}.1"
START_OCTET = 200
END_OCTET = 210

SSH_TIMEOUT = 12        # seconds for connect
CMD_TIMEOUT = 20        # seconds to wait for command output
MAX_WORKERS = 20

# Commands we will run (we send them on one shell)
BASE_COMMANDS = [
    "terminal length 0",
    "show version",
    "show inventory",
]

# Extra probes that may return modem/firmware info (varies by platform)
CELL_PROBES = [
    "show cellular 0 all",
    "show cellular 0/0/0 all",
    "show control-plane cellular",
    "show controllers cellular 0/0/0",
    "show platform hardware qfp active infrastructure",  # keeps generic, may be noisy
]

# Regexes
IMAGE_RE = re.compile(r"\(([^)]+UNIVERSALK9[^)]*)\)", re.IGNORECASE)
VERSION_RE = re.compile(r"Version\s+([0-9A-Za-z().\-+]+)", re.IGNORECASE)
IOSXE_VERSION_RE = re.compile(r"Cisco IOS XE Software.*Version\s+([0-9A-Za-z().\-+]+)", re.IGNORECASE)
MODEM_FW_RE = re.compile(r"(Firmware|Firmware Version|Modem Firmware|Modem Fw|Bootloader|Revision|SW Version|Software Version)[\s:]+([^\r\n]+)", re.IGNORECASE)
MODEL_LINE_RE = re.compile(r"^Cisco IOS Software.*\(([^)]+)\)|^Cisco .*\(.*\)", re.IGNORECASE)

# -----------------------------
# Helper functions
# -----------------------------

def build_hosts(start: int, end: int, template: str) -> List[str]:
    return [template.format(x=i) for i in range(start, end + 1)]

def connect_and_collect(host: str) -> dict:
    """
    Connects with Paramiko invoke_shell, runs commands, collects output,
    parses image, version, and modem firmware if present.
    """
    result = {
        "host": host,
        "model_image": "",
        "version": "",
        "modem_firmware": "",
        "raw_first_line": "",
        "status": "unknown",
    }

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, username=USERNAME, password=PASSWORD,
                       look_for_keys=False, allow_agent=False,
                       timeout=SSH_TIMEOUT, auth_timeout=SSH_TIMEOUT)
        chan = client.invoke_shell()
        chan.settimeout(2.0)

        def send(cmd: str):
            chan.send(cmd + "\n")
            time.sleep(0.15)

        # Send the base commands
        send("")  # blank to get prompt
        for c in BASE_COMMANDS:
            send(c)

        # Also try the cellular probes (some will produce errors quickly if unsupported)
        for p in CELL_PROBES:
            send(p)

        # Read until prompt or timeout
        buffer = ""
        start = time.time()
        while time.time() - start < CMD_TIMEOUT:
            try:
                chunk = chan.recv(65535).decode("utf-8", errors="ignore")
                if chunk:
                    buffer += chunk
                    # quick heuristic for prompt detection: line ends with routername# or >
                    if re.search(r"\n[\w\-\.\:]+[#>]\s*$", buffer):
                        # allow a small grace period for trailing data
                        time.sleep(0.1)
                        break
                else:
                    time.sleep(0.1)
            except socket.timeout:
                # keep waiting until CMD_TIMEOUT
                pass

        chan.close()
        client.close()

        # Parse for "first line" mentioning IOS or IOS XE
        first_line = ""
        for line in buffer.splitlines():
            if "Cisco IOS" in line or "Cisco IOS XE" in line or "Cisco IOS Software" in line:
                first_line = line.strip()
                break
        result["raw_first_line"] = first_line

        # MODEL / IMAGE
        m_img = IMAGE_RE.search(buffer)
        if m_img:
            result["model_image"] = m_img.group(1).strip()
        else:
            # fallback heuristics: look in "show version" for platform string
            for line in buffer.splitlines():
                line = line.strip()
                # many show version outputs contain something like "cisco 1921 (revision ... )"
                if "processor" in line.lower() and "(" in line:
                    # just capture rough piece
                    result["model_image"] = line[:80]
                    break

        # VERSION
        m_ver = VERSION_RE.search(first_line or buffer)
        if m_ver:
            result["version"] = m_ver.group(1).strip()
        else:
            m_xe = IOSXE_VERSION_RE.search(buffer)
            if m_xe:
                result["version"] = m_xe.group(1).strip()

        # MODEM / FIRMWARE
        # collect all matches
        fw_matches = []
        for m in MODEM_FW_RE.finditer(buffer):
            key = m.group(1).strip()
            val = m.group(2).strip()
            fw_matches.append(f"{key}: {val}")

        # If none found, try to find lines containing 'modem' or 'cell' near 'firmware'
        if not fw_matches:
            for i, line in enumerate(buffer.splitlines()):
                low = line.lower()
                if "modem" in low or "cell" in low or "firmware" in low or "revision" in low:
                    # capture a small window of lines
                    window = buffer.splitlines()[max(0, i-2):i+3]
                    txt = " | ".join([l.strip() for l in window if l.strip()])
                    if txt and len(txt) < 500:
                        fw_matches.append(txt)

        result["modem_firmware"] = "; ".join(fw_matches[:3])  # limit length

        result["status"] = "ok" if (result["model_image"] or result["version"]) else "parse_failed"
        return result

    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        result["status"] = f"error: {type(e).__name__}: {e}"
        return result

# -----------------------------
# Main
# -----------------------------
def main():
    hosts = build_hosts(START_OCTET, END_OCTET, SUBNET_TEMPLATE)
    print(f"Scanning {len(hosts)} hosts: {hosts[0]} .. {hosts[-1]}")

    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_map = {ex.submit(connect_and_collect, h): h for h in hosts}
        for fut in as_completed(future_map):
            res = fut.result()
            print(f"{res['host']}: {res['status']}")
            results.append(res)

    df = pd.DataFrame(results, columns=["host", "model_image", "version", "modem_firmware", "raw_first_line", "status"])
    out_xlsx = "router_versions.xlsx"
    out_csv = "router_versions.csv"
    df.to_excel(out_xlsx, index=False)
    df.to_csv(out_csv, index=False)
    print(f"Saved {out_xlsx} and {out_csv}")
    print(df)

if __name__ == "__main__":
    main()
