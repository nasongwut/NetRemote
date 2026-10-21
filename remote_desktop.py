#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRemote — โปรแกรม Remote Desktop (ค้นหาเครื่องผ่าน Relay Server · เชื่อมต่อตรงเมื่อทำได้)
=====================================================================
ดูหน้าจอ + ควบคุมเมาส์/คีย์บอร์ด + รับ-ส่งไฟล์ ของอีกเครื่องด้วย ID 9 หลัก
- ตั้งค่า Relay ได้ในโปรแกรม หรือไฟล์ .env (RELAY_ADDR / RELAY_KEY) — ดู .env.example
- เข้ารหัสทั้งหมดด้วย TLS (สร้าง Certificate ให้เองอัตโนมัติ)
- ยืนยันตัวตนด้วยรหัสผ่าน (HMAC ผูกกับ Certificate ป้องกันการดักกลางทาง)
- ส่งเฉพาะส่วนของหน้าจอที่เปลี่ยน (ประหยัดเน็ต)
- รองรับหลายจอ, ปรับคุณภาพภาพ, โหมดดูอย่างเดียว, ถามก่อนรับการเชื่อมต่อ
- ค้นหาเครื่องที่เปิดรับการเชื่อมต่อในวง LAN

ต้องติดตั้ง:  pip install mss Pillow pynput cryptography
(ไฟล์ "Run on Mac.command" จะติดตั้งให้อัตโนมัติในครั้งแรก)

ใช้งาน:
    python3 remote_desktop.py                         เปิดหน้าต่างโปรแกรม
    python3 remote_desktop.py --server [--password X] เปิดรับการเชื่อมต่อแบบไม่มีหน้าต่าง
"""
import argparse
import base64
import errno
import glob
import hashlib
import hmac
import io
import ipaddress
import json
import os
import platform
import queue
import re
import secrets
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

if sys.stdout is None:                       # โปรแกรมแบบ .app / .exe ไม่มี console
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

APP = "NetRemote"
VERSION = "1.6"
PROTO = 1
DEFAULT_PORT = 5905
SYSTEM = platform.system()
CONF_DIR = os.path.join(os.path.expanduser("~"), ".netremote")
CONF_FILE = os.path.join(CONF_DIR, "config.json")
CERT_FILE = os.path.join(CONF_DIR, "cert.pem")
KEY_FILE = os.path.join(CONF_DIR, "key.pem")

# ----------------------------------------------------------------------------
# ไฟล์ .env (ตั้งค่าโดยผู้ดูแล) — ค่าใน .env มีผลเหนือค่าที่ตั้งในโปรแกรม
#   ลำดับการค้นหา: $NETREMOTE_ENV → ~/.netremote/.env → โฟลเดอร์ของโปรแกรม → ฝังมากับโปรแกรม (ตอน Build)
# ----------------------------------------------------------------------------
def _parse_env(path):
    out = {}
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            if k.startswith("export "):
                k = k[7:].strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            elif " #" in v:
                v = v.split(" #", 1)[0].strip()
            out[k] = v
    return out


def env_candidates():
    paths = []
    if os.environ.get("NETREMOTE_ENV"):
        paths.append(os.environ["NETREMOTE_ENV"])
    paths.append(os.path.join(CONF_DIR, ".env"))
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        if ".app/Contents/MacOS" in exe_dir:                       # macOS .app → โฟลเดอร์ที่วาง .app
            paths.append(os.path.join(exe_dir.split(".app/Contents/MacOS")[0].rsplit("/", 1)[0], ".env"))
        paths.append(os.path.join(exe_dir, ".env"))
        if getattr(sys, "_MEIPASS", None):
            paths.append(os.path.join(sys._MEIPASS, ".env"))      # ฝังมากับโปรแกรมตอน Build
    else:
        paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    return paths


def load_env():
    for p in env_candidates():
        try:
            if os.path.isfile(p):
                return _parse_env(p), p
        except Exception:
            pass
    return {}, None


ENV, ENV_PATH = load_env()


def env_str(key, default=""):
    v = ENV.get(key, "")
    return v if v != "" else default


def env_bool(key, default):
    v = ENV.get(key, "").strip().lower()
    if v in ("1", "true", "yes", "on", "y"):
        return True
    if v in ("0", "false", "no", "off", "n"):
        return False
    return default


# ============================================================================
# ภาษา (ไทย / English) — เริ่มต้นเป็น English · เปลี่ยนได้ที่ปุ่มมุมขวาบน หรือ LANGUAGE=th/en ในไฟล์ .env
# ============================================================================
def _detect_lang():
    v = ENV.get("LANGUAGE", "").strip().lower()[:2]
    if v in ("th", "en"):
        return v
    try:
        with open(CONF_FILE, encoding="utf-8") as f:
            v = json.load(f).get("lang")
        if v in ("th", "en"):
            return v
    except Exception:
        pass
    return "en"                                      # ภาษาเริ่มต้น = English


LANG = _detect_lang()
RESTART = []
_EN = {
    '%s กำลังควบคุมเครื่องนี้': '%s is controlling this computer',
    'กำลังควบคุมเครื่องนี้': 'Controlling this computer',
    'กำลังส่ง…': 'Sending…',
    'กำลังส่ง… %d%%': 'Sending… %d%%',
    'กำลังโทร…': 'Calling…',
    'ตัดสาย': 'End',
    'ปฏิเสธ': 'Decline',
    'ปล่อยปุ่ม': 'Keys',
    'ปิดไมค์': 'Muted',
    'พิมพ์': 'Type',
    'พิมพ์ข้อความ…': 'Type a message…',
    'รับด้วยเสียงอย่างเดียว': 'Answer with audio only',
    'วันนี้': 'Today',
    'วีดีโอคอล': 'Video call',
    'ส่งแล้ว': 'Sent',
    'อ่านแล้ว': 'Read',
    'เครื่องปลายทางใช้โปรแกรมเวอร์ชันเก่าที่ยังไม่มีแชท': 'The remote computer runs an older version without chat',
    'เต็มจอ': 'Full',
    'เปิดกล้องไม่ได้ — ไม่พบกล้อง หรือกล้องถูกโปรแกรมอื่นใช้อยู่': "Can't open the camera — no camera found, or it's being used by another app",
    'เมื่อสักครู่': 'just now',
    'โทรเสียง': 'Voice call',
    'ได้รับแล้ว': 'Received',
    'ไม่ตอบสนอง': 'Not responding',
    'ไม่มีสิทธิ์เขียนไฟล์ในโฟลเดอร์ของโปรแกรม — ย้ายโปรแกรมไปไว้ที่โฟลเดอร์อื่น (เช่น Desktop) แล้วลองใหม่': "No permission to write in the app's folder — move the app to another folder (e.g. Desktop) and try again",
"ดีมาก": "Excellent",
"ดี": "Good",
"พอใช้": "Fair",
"ช้า": "Slow",
"ประหยัด": "Low data",
"ปกติ": "Normal",
"คมชัด": "Sharp",
"สูงสุด": "Maximum",
"Keychain ของ macOS": "macOS Keychain",
"ไฟล์ ~/.netremote (อ่านได้เฉพาะผู้ใช้นี้)": "file in ~/.netremote (readable by this user only)",
"การเชื่อมต่อถูกปิด": "Connection closed",
"อีกฝั่งปิดการเชื่อมต่อ": "The other side closed the connection",
"อีกฝั่งตัดการเชื่อมต่อ": "The other side disconnected",
"ไม่ได้รับข้อมูลนานเกินไป (หมดเวลา)": "No data received for too long (timed out)",
"ตัดการเชื่อมต่อแล้ว": "Disconnected",
"เครื่องปลายทางตัดการเชื่อมต่อ": "The remote computer disconnected",
"ยังไม่ได้ตั้งค่า Server\n\nตั้งค่าที่แท็บ \"ตั้งค่า Server\"": "Server is not set up yet\n\nSet it up in the \"Server Settings\" tab",
"ปิดการรับการเชื่อมต่อแล้ว": "Stopped accepting connections",
"รหัสผ่านไม่ถูกต้อง": "Incorrect password",
"⚠ %s (%s) ใส่รหัสผ่านผิด%s": "⚠ %s (%s) entered a wrong password%s",
" — บล็อก 60 วินาที": " — blocked for 60 seconds",
"เครื่องนี้มีผู้เชื่อมต่ออยู่แล้ว": "This computer already has a connected user",
"%s (%s) ขอเชื่อมต่อ — รอการยืนยัน": "%s (%s) wants to connect — waiting for approval",
"เครื่องปลายทางปฏิเสธการเชื่อมต่อ": "The remote computer declined the connection",
"ปฏิเสธการเชื่อมต่อจาก %s (%s)": "Declined connection from %s (%s)",
"ผิดพลาด: %s": "Error: %s",
"⚠ ควบคุมเมาส์/คีย์บอร์ดไม่ได้: %s": "⚠ Cannot control mouse/keyboard: %s",
"ผิดพลาดระหว่างเชื่อมต่อ: %s": "Error while connected: %s",
"เครื่องปลายทางผิดพลาด: %s": "Remote computer error: %s",
"● %s (%s) เชื่อมต่อแล้ว": "● %s (%s) connected",
"เครื่องนี้ตัดการเชื่อมต่อ": "This computer disconnected",
"○ %s (%s) ออกจากการเชื่อมต่อ — %s": "○ %s (%s) left — %s",
"ควบคุมไม่สำเร็จ: %s": "Control failed: %s",
"ไม่มีสิทธิ์เข้าถึง": "Permission denied",
"ไม่พบไฟล์หรือโฟลเดอร์": "File or folder not found",
"มีชื่อนี้อยู่แล้ว": "This name already exists",
"ชื่อไฟล์ไม่ถูกต้อง: %s": "Invalid file name: %s",
"เครื่องปลายทางไม่อนุญาตให้รับ-ส่งไฟล์": "The remote computer does not allow file transfer",
"🗑 %s ลบ %d รายการ": "🗑 %s deleted %d item(s)",
"ลบไม่สำเร็จบางรายการ — ": "Some items could not be deleted — ",
"ชื่อโฟลเดอร์ไม่ถูกต้อง": "Invalid folder name",
"ไม่พบโฟลเดอร์ปลายทาง": "Destination folder not found",
"ไม่พบการอัปโหลดนี้": "Upload not found",
"⬆ ได้รับไฟล์ %s (%s) จาก %s": "⬆ Received %s (%s) from %s",
"⬇ ส่งไฟล์ %d ไฟล์ (%s) ให้ %s": "⬇ Sent %d file(s) (%s) to %s",
"กำลังเริ่ม…": "Starting…",
" และอีก %d รายการ": " and %d more",
"ปลายทางไม่ตอบสนอง": "The remote computer is not responding",
"ผิดพลาด": "Error",
"ไม่มีไฟล์ให้ส่ง": "No files to send",
"กำลังส่ง %d/%d  %s": "Sending %d/%d  %s",
"การเชื่อมต่อถูกตัด": "Connection lost",
"กำลังเตรียมไฟล์…": "Preparing files…",
"กำลังรับ %d/%d  %s": "Receiving %d/%d  %s",
"ไม่มีไฟล์ (โฟลเดอร์ว่าง)": "No files (empty folder)",
"✓ เสร็จ (%d ไฟล์)": "✓ Done (%d files)",
"ยกเลิกแล้ว": "Cancelled",
"การดาวน์โหลดถูกตัดกลางทาง": "Download was interrupted",
"ผู้ดูแล Server สั่งตัดการเชื่อมต่อ": "Server administrator ended the connection",
"ถูกปฏิเสธ": "Refused",
"จอ %d (%d×%d)": "Screen %d (%d×%d)",
"ควบคุม": "Control",
"สลับ ⌘↔Ctrl": "Swap ⌘↔Ctrl",
"ตัดการเชื่อมต่อ": "Disconnect",
"⛶ เต็มจอ": "⛶ Full screen",
"⟲ ปล่อยปุ่ม": "⟲ Release keys",
"✎ ข้อความ": "✎ Text",
"📁 ไฟล์": "📁 Files",
"กำลังรับภาพหน้าจอ…": "Receiving screen…",
"เชื่อมต่อแล้ว": "Connected",
"●  ไม่ตอบสนอง": "●  Not responding",
"ควบคุมได้": "Control enabled",
"ดูอย่างเดียว": "View only",
"เปิด \"ควบคุมเมาส์/คีย์บอร์ด\" ก่อน": "Turn on \"Control\" first",
"พิมพ์ข้อความที่จะส่งไปพิมพ์บนเครื่องปลายทาง\n(รองรับภาษาไทย — คลิกช่องที่ต้องการพิมพ์บนเครื่องปลายทางไว้ก่อน)": "Type the text to send to the remote computer\n(Thai supported — click the target field on the remote computer first)",
"เครื่องปลายทาง (%s) ใช้โปรแกรม NetRemote เวอร์ชันเก่า ที่ยังไม่รองรับการรับ-ส่งไฟล์\n\nให้อัปเดตโปรแกรมบนเครื่องปลายทางเป็นเวอร์ชันล่าสุด แล้วเชื่อมต่อใหม่": "The remote computer (%s) runs an older NetRemote version that does not support file transfer\n\nUpdate the program on the remote computer to the latest version, then reconnect",
"เครื่องปลายทาง (%s) ปิดการรับ-ส่งไฟล์ไว้\n\nที่เครื่องปลายทาง: แท็บ \"ให้เครื่องอื่นควบคุมเครื่องนี้\" → ติ๊ก \"อนุญาตให้รับ-ส่งไฟล์\" แล้วเชื่อมต่อใหม่": "The remote computer (%s) has file transfer turned off\n\nOn the remote computer: \"Let Others Control This Computer\" tab → tick \"Allow file transfer\", then reconnect",
"⬆ ขึ้น": "⬆ Up",
"ไดรฟ์": "Drives",
"เลือกได้หลายรายการ (กด ⌘/Ctrl หรือ Shift ค้าง) — เลือกโฟลเดอร์ได้ด้วย ดับเบิลคลิกโฟลเดอร์เพื่อเปิด": "Multiple selection (hold ⌘/Ctrl or Shift) — folders can be selected too. Double-click a folder to open it",
"เปิดโฟลเดอร์ที่ต้องการ แล้วกด \"เลือกโฟลเดอร์นี้\" (หรือคลิกเลือกโฟลเดอร์ย่อย)": "Open the folder you want, then press \"Choose This Folder\" (or click a subfolder)",
"ชื่อ": "Name",
"ขนาด": "Size",
"แก้ไขล่าสุด": "Modified",
"ยกเลิก": "Cancel",
"เลือก": "Select",
"เลือกโฟลเดอร์นี้": "Choose This Folder",
"เปิดโฟลเดอร์ไม่ได้: %s": "Cannot open folder: %s",
"เลือก %d รายการ": "Select %d item(s)",
"คลิกเลือกไฟล์หรือโฟลเดอร์ก่อน": "Click a file or folder first",
"+ โฟลเดอร์ใหม่": "+ New folder",
"✕ ลบ": "✕ Delete",
"กำลังโหลด…": "Loading…",
"(ไดรฟ์ทั้งหมด)": "(All drives)",
"%d โฟลเดอร์ · %d ไฟล์": "%d folders · %d files",
"ชื่อโฟลเดอร์ใหม่:": "New folder name:",
"สร้างโฟลเดอร์ไม่ได้: %s": "Cannot create folder: %s",
"เครื่องนี้": "This device",
"เครื่องปลายทาง": "Remote device",
"\n… และอีก %d รายการ": "\n… and %d more",
" (ย้ายไปถังขยะ)": " (moved to Trash)",
"ลบ %d รายการบน%s%s?\n\n%s%s": "Delete %d item(s) on %s%s?\n\n%s%s",
"ลบไม่สำเร็จบางรายการ:\n": "Some items could not be deleted:\n",
"รับ-ส่งไฟล์ — %s": "File Transfer — %s",
"เครื่องนี้ · This device": "This device",
"เครื่องปลายทาง · Remote device": "Remote device",
"การรับ-ส่งไฟล์": "Transfers",
"ล้างรายการที่เสร็จแล้ว": "Clear finished",
"ยกเลิกที่เลือก": "Cancel selected",
"ลากไฟล์ข้ามฝั่งเพื่อส่งได้": "Drag files across to transfer",
"ไฟล์": "File",
"ความคืบหน้า": "Progress",
"ความเร็ว": "Speed",
"สถานะ": "Status",
"เลือกไฟล์หรือโฟลเดอร์ฝั่งซ้าย (เครื่องนี้) ที่จะส่งก่อน": "Select files or folders on the left (this device) to send first",
"เปิดโฟลเดอร์ปลายทางฝั่งขวาก่อน": "Open a destination folder on the right first",
"เลือกไฟล์หรือโฟลเดอร์ฝั่งขวา (เครื่องปลายทาง) ที่จะดาวน์โหลดก่อน": "Select files or folders on the right (remote device) to download first",
"เปิดโฟลเดอร์ปลายทางฝั่งซ้ายก่อน": "Open a destination folder on the left first",
"✓ %s เสร็จ: %s": "✓ %s done: %s",
"◐  อัตโนมัติ": "◐  Auto",
"☀  สว่าง": "☀  Light",
"☾  มืด": "☾  Dark",
"ควบคุมเครื่องอื่น": "Control Another Computer",
"ให้เครื่องอื่นควบคุมเครื่องนี้": "Let Others Control This Computer",
"ตั้งค่า Server": "Server Settings",
"●  Server: กำลังตรวจสอบ…": "●  Server: checking…",
"เชื่อมต่อไปยังเครื่องอื่น": "Connect to another computer",
"ID เครื่องปลายทาง": "Remote computer ID",
"รหัสผ่าน": "Password",
"👁 แสดง": "👁 Show",
"จดจำรหัสผ่านของเครื่องนี้": "Remember this computer's password",
"ดูหน้าจออย่างเดียว (ไม่ควบคุม)": "View screen only (no control)",
"เชื่อมต่อ   →": "Connect   →",
"เครื่องที่เคยเชื่อมต่อ": "Recent computers",
"ล้างทั้งหมด": "Clear all",
"ดับเบิลคลิกเพื่อรีโมททันที (ถ้าจดจำรหัสผ่านไว้) · คลิกขวาเพื่อดูเมนู": "Double-click to connect instantly (if the password is remembered) · Right-click for menu",
"ชื่อเครื่อง": "Computer name",
"รหัส": "🔑",
"ล่าสุด": "Last used",
"▶  เชื่อมต่อ": "▶  Connect",
"✎ เปลี่ยนชื่อ": "✎ Rename",
"✎  เปลี่ยนชื่อ…": "✎  Rename…",
"⧉  คัดลอก ID": "⧉  Copy ID",
"🔑  ลืมรหัสผ่าน": "🔑  Forget password",
"✕  ลบออกจากรายการ": "✕  Remove from list",
"🙈 ซ่อน": "🙈 Hide",
"เลือกเครื่องจากรายการก่อน": "Select a computer from the list first",
"ใส่รหัสผ่านของ %s แล้วกดเชื่อมต่อ (ติ๊ก \"จดจำรหัสผ่าน\" เพื่อครั้งหน้ากดครั้งเดียว)": "Enter the password for %s and press Connect (tick \"Remember password\" for one-click next time)",
"ตั้งชื่อเรียกเครื่อง ID %s\n(เว้นว่าง = ใช้ชื่อจริงของเครื่อง: %s)": "Set a nickname for ID %s\n(leave blank = use the computer's real name: %s)",
"ลบ %s (%s) ออกจากรายการ?\n(รหัสผ่านที่จดจำไว้จะถูกลบด้วย)": "Remove %s (%s) from the list?\n(Its remembered password will also be deleted)",
"ล้างรายการเครื่องที่เคยเชื่อมต่อทั้งหมด และรหัสผ่านที่จดจำไว้?": "Clear all recent computers and remembered passwords?",
"กรุณาใส่ ID 9 หลักของเครื่องปลายทาง\n(ดู ID ได้ที่แท็บ \"ให้เครื่องอื่นควบคุมเครื่องนี้\" ของเครื่องนั้น)": "Please enter the 9-digit ID of the remote computer\n(The ID is shown in the \"Let Others Control This Computer\" tab on that computer)",
"กรุณาใส่รหัสผ่าน": "Please enter the password",
"ยังไม่ได้ตั้งค่า Server\nไปที่แท็บ \"ตั้งค่า Server\"": "Server is not set up yet\nGo to the \"Server Settings\" tab",
"กำลังเชื่อมต่อ %s … (ถ้าปลายทางตั้งให้ถามก่อน ต้องรอให้กดยอมรับ)": "Connecting to %s … (if the remote side asks first, wait for them to accept)",
"หมดเวลา — ไม่มีการตอบรับจาก %s": "Timed out — no response from %s",
"เชื่อมต่อ %s ไม่ได้: %s": "Cannot connect to %s: %s",
"▶   เริ่มเปิดรับการเชื่อมต่อ": "▶   Start accepting connections",
"ข้อมูลสำหรับให้อีกฝั่งเชื่อมต่อ": "Connection details for the other side",
"ID ของเครื่องนี้": "This computer's ID",
"สุ่มใหม่": "New random",
"คัดลอก": "Copy",
"ตัวเลือก": "Options",
"ถามก่อนรับการเชื่อมต่อ": "Ask before accepting a connection",
"อนุญาตให้ควบคุมเมาส์/คีย์บอร์ด": "Allow mouse/keyboard control",
"อนุญาตให้รับ-ส่งไฟล์": "Allow file transfer",
"สิทธิ์ของ macOS": "macOS permissions",
"ให้สิทธิ์กับแอป %s": "Grant permissions to the app %s",
"Screen Recording\nให้อีกฝั่งเห็นหน้าจอ": "Screen Recording\nlets the other side see the screen",
"Accessibility\nให้อีกฝั่งควบคุมได้": "Accessibility\nlets the other side control it",
"เปิดการตั้งค่า": "Open Settings",
"บันทึกเหตุการณ์": "Event log",
"(สร้างเมื่อเริ่มเปิดรับครั้งแรก)": "(created when you first start accepting)",
"ที่อยู่ Server": "Server address",
"เช่น relay.example.com:5910 หรือ 203.0.113.10:5910": "e.g. relay.example.com:5910 or 203.0.113.10:5910",
"🔒  ตั้งค่าไว้โดยผู้ดูแลระบบ": "🔒  Set by your administrator",
"บันทึก": "Save",
"ทดสอบการเชื่อมต่อ": "Test connection",
"อัปเดตโปรแกรม": "Program updates",
"ตรวจสอบอัปเดต": "Check for updates",
"ยังไม่ได้ตรวจสอบ": "Not checked yet",
"⬇  ดาวน์โหลดเวอร์ชันใหม่": "⬇  Download new version",
"ให้อีกฝั่งใส่ ID นี้เพื่อเชื่อมต่อเข้ามา": "Give this ID to the other side so they can connect",
"สร้าง ID ใหม่": "Create new ID",
"สถานะการเชื่อมต่อ Server": "Server connection status",
"รับการเชื่อมต่อของเครื่องนี้": "Accepting connections on this computer",
"ตรวจล่าสุด": "Last checked",
"ยังไม่ได้ตั้งค่า Server": "Server is not set up yet",
"กำลังตรวจสอบ…": "Checking…",
"✗ ตรวจสอบไม่ได้: %s": "✗ Could not check: %s",
"✓ ใช้เวอร์ชันล่าสุดอยู่แล้ว (%s)": "✓ You are on the latest version (%s)",
"⬆ มีเวอร์ชันใหม่: %s  (ใช้อยู่ %s)": "⬆ New version available: %s  (current %s)",
"⬇  ดาวน์โหลด %s (%s)": "⬇  Download %s (%s)",
"🌐  เปิดหน้าดาวน์โหลด": "🌐  Open download page",
"⬆  มีอัปเดต %s": "⬆  Update %s",
"⬆ มีโปรแกรมเวอร์ชันใหม่ %s — ดูที่แท็บ \"ตั้งค่า Server\"": "⬆ New program version %s — see the \"Server Settings\" tab",
"ยกเลิกการดาวน์โหลด": "Cancel download",
"✗ ดาวน์โหลดไม่สำเร็จ: %s": "✗ Download failed: %s",
"ปิดโปรแกรมนี้ แล้วใช้ไฟล์ใหม่แทนตัวเดิม": "Quit this program, then use the new file in place of the old one",
"ปิดโปรแกรมนี้ แล้วใช้ไฟล์ %s แทนไฟล์ NetRemote.exe ตัวเดิม": "Quit this program, then use %s in place of the old NetRemote.exe",
"ไฟล์อยู่ที่ %s": "The file is at %s",
"ดาวน์โหลดเวอร์ชันใหม่เรียบร้อย\n\n%s": "New version downloaded\n\n%s",
"รูปแบบที่อยู่ Server ไม่ถูกต้อง (เช่น relay.example.com:5910)": "Invalid Server address (e.g. relay.example.com:5910)",
"บันทึกแล้ว — กำลังเชื่อมต่อ Server ใหม่": "Saved — reconnecting to the Server",
"ใส่ที่อยู่ Server ก่อน": "Enter the Server address first",
"กำลังทดสอบ %s …": "Testing %s …",
"สร้าง ID ใหม่? ผู้ที่เคยเชื่อมต่อด้วย ID เดิมจะต้องใช้ ID ใหม่": "Create a new ID? Anyone who connected with the old ID will need the new one",
"ยังไม่ได้ตั้งค่า Server — ตั้งที่แท็บ \"ตั้งค่า Server\"": "Server is not set up yet — set it in the \"Server Settings\" tab",
"หยุดรับการเชื่อมต่ออยู่ — กด \"เริ่มเปิดรับการเชื่อมต่อ\"": "Not accepting connections — press \"Start accepting connections\"",
"○  ยังไม่ได้ตั้งค่า Server": "○  Server not set up",
"●  Server: เชื่อมต่อไม่ได้": "●  Server: cannot connect",
"●  Server: กำลังเชื่อมต่อ…": "●  Server: connecting…",
"✓ ออนไลน์": "✓ Online",
"✗ เชื่อมต่อไม่ได้": "✗ Cannot connect",
"ยังไม่ได้ตั้งค่า": "Not set up",
"● ออนไลน์ — ID %s": "● Online — ID %s",
"หยุดรับการเชื่อมต่ออยู่": "Not accepting connections",
"NetRemote — ID: %s  รหัสผ่าน: %s": "NetRemote — ID: %s  Password: %s",
"คัดลอกข้อมูลการเชื่อมต่อแล้ว": "Connection details copied",
"✓ อนุญาตแล้ว": "✓ Allowed",
"✗ ยังไม่อนุญาต": "✗ Not allowed yet",
"? ตรวจไม่ได้": "? Cannot check",
"▶  เริ่มเปิดรับการเชื่อมต่อ": "▶  Start accepting connections",
"รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร": "Password must be at least 6 characters",
"ยังไม่ได้ตั้งค่า Server\n\nไปที่แท็บ \"ตั้งค่า Server\"": "Server is not set up yet\n\nGo to the \"Server Settings\" tab",
"เริ่มไม่ได้: %s": "Cannot start: %s",
"■  หยุดเปิดรับ": "■  Stop accepting",
"⚠ ยังไม่ได้อนุญาต Screen Recording — อีกฝั่งจะเห็นแค่ภาพพื้นหลัง": "⚠ Screen Recording not allowed — the other side will only see the wallpaper",
"⚠ ยังไม่ได้อนุญาต Accessibility — อีกฝั่งจะควบคุมไม่ได้": "⚠ Accessibility not allowed — the other side cannot control this computer",
"○   หยุดรับการเชื่อมต่อชั่วคราว": "○   Paused accepting connections",
"○   ยังไม่พร้อมรับการเชื่อมต่อ": "○   Not ready for connections",
"กด \"เริ่มเปิดรับการเชื่อมต่อ\" เพื่อให้เครื่องอื่นเชื่อมต่อเข้ามาได้อีกครั้ง": "Press \"Start accepting connections\" to let other computers connect again",
"●   พร้อมรับการเชื่อมต่อ": "●   Ready for connections",
"●   กำลังถูกควบคุมอยู่": "●   Being controlled",
"โดย %s": "by %s",
"■   หยุดเปิดรับ": "■   Stop accepting",
"การเชื่อมต่อกับ %s สิ้นสุด\n%s": "Connection with %s ended\n%s",
"%s (%s)\nขอเชื่อมต่อเพื่อ%sเครื่องนี้\n\nอนุญาตหรือไม่?": "%s (%s)\nwants to connect to %s this computer\n\nAllow?",
"ดูหน้าจอ": "view",
"กำลังดาวน์โหลด… %s / %s": "Downloading… %s / %s",
"โดย %s   ·   Latency %.0f ms (%s)": "by %s   ·   Latency %.0f ms (%s)",
"ต้องระบุ Relay Server: --relay HOST:PORT หรือใส่ RELAY_ADDR ในไฟล์ .env": "Relay Server required: --relay HOST:PORT or set RELAY_ADDR in the .env file",
"%s %s — เปิดรับการเชื่อมต่อผ่าน Relay": "%s %s — accepting connections via Relay",
"  รหัสผ่าน : %s": "  Password : %s",
"กด Ctrl+C เพื่อหยุด\n": "Press Ctrl+C to stop\n",
"\nหยุดแล้ว": "\nStopped",
"NetRemote — Remote Desktop ผ่าน Relay": "NetRemote — Remote Desktop via Relay",
"เปิดรับการเชื่อมต่อแบบไม่มีหน้าต่าง": "Accept connections without a window",
"รหัสผ่าน (โหมด --server)": "Password (--server mode)",
"ให้ดูหน้าจออย่างเดียว (โหมด --server)": "View only (--server mode)",
"ไม่อนุญาตรับ-ส่งไฟล์ (โหมด --server)": "Do not allow file transfer (--server mode)",
"Relay Server เช่น relay.example.com:5910 (หรือ RELAY_ADDR ใน .env)": "Relay Server e.g. relay.example.com:5910 (or RELAY_ADDR in .env)",
"ยังไม่ได้ติดตั้ง: pip install ": "Not installed: pip install ",
"%s (%s)\nขอเชื่อมต่อเพื่อควบคุมเครื่องนี้\n\nอนุญาตหรือไม่?": "%s (%s)\nwants to connect and control this computer\n\nAllow?",
"%s (%s)\nขอเชื่อมต่อเพื่อดูหน้าจอเครื่องนี้\n\nอนุญาตหรือไม่?": "%s (%s)\nwants to connect and view this computer's screen\n\nAllow?",
"เปลี่ยนภาษาเป็น English?\n\nโปรแกรมจะเปิดใหม่ (การเชื่อมต่อที่เปิดอยู่จะถูกตัด)": "Switch language to Thai (ภาษาไทย)?\n\nThe program will restart (open connections will be closed)",
"ไม่พบเครื่อง ID %s หรือเครื่องนั้นไม่ได้เปิดรับการเชื่อมต่อ": "Computer ID %s not found, or it is not accepting connections",
"Relay มีผู้ใช้งานเต็มแล้ว ลองใหม่ภายหลัง": "The Relay is full, please try again later",
"เครื่องปลายทางไม่ตอบสนอง": "The remote computer is not responding",
"Relay Key ไม่ถูกต้อง": "Invalid Server Key",
"ID ไม่ถูกต้อง": "Invalid ID",
"ID นี้ถูกใช้โดยเครื่องอื่นแล้ว — สร้าง ID ใหม่": "This ID is already used by another computer — create a new ID",
"Remote Desktop · v%s": "Remote Desktop · v%s",
"ใส่ ID 9 หลักและรหัสผ่านของเครื่องที่ต้องการควบคุม": "Enter the 9-digit ID and password of the computer you want to control",
"🔒  การเชื่อมต่อทั้งหมดเข้ารหัสอย่างปลอดภัย": "🔒  All connections are securely encrypted",
"🔑  รหัสผ่านที่จดจำถูกเก็บอย่างปลอดภัยในเครื่องนี้": "🔑  Remembered passwords are stored securely on this computer",
"ใส่ที่อยู่ Server และ Server Key ที่ได้รับจากผู้ดูแลระบบ": "Enter the Server address and Server Key from your administrator",
"รายละเอียด": "Details",
"ใช้งานได้ปกติ": "Working normally",
"●  เชื่อมต่อ Server แล้ว": "●  Connected to Server",
"✓ เชื่อมต่อ Server ได้ ใช้งานได้ปกติ": "✓ Connected to the Server — working normally",
" · พร้อมรับการเชื่อมต่อ": " · ready for connections",
"เวอร์ชันที่ใช้อยู่: %s": "Current version: %s",
"(ยังไม่มีไฟล์สำหรับเครื่องนี้ — ติดต่อผู้ดูแลระบบ)": "(No download for this computer yet — contact your administrator)",
"✓ ใช้เวอร์ชันล่าสุดอยู่แล้ว": "✓ You are on the latest version",
"✓ ดาวน์โหลดเรียบร้อย: %s": "✓ Downloaded: %s",
"ไฟล์ที่ดาวน์โหลดไม่สมบูรณ์ — ลองดาวน์โหลดใหม่": "The download is incomplete — please try again",
"เชื่อมต่อกับ %s (%s)  ·  %s": "Connected to %s (%s)  ·  %s",
"พร้อมรับการเชื่อมต่อ — ID %s": "Ready for connections — ID %s",
"กำลังเชื่อมต่อ Server …": "Connecting to the Server …",
"ออนไลน์ — พร้อมรับการเชื่อมต่อ": "Online — ready for connections",
"เชื่อมต่อ Server แล้ว — ID %s": "Connected to the Server — ID %s",
"Server ไม่ตอบสนอง": "The Server is not responding",
"ปิดการเชื่อมต่อ Server แล้ว": "Disconnected from the Server",
"เชื่อมต่อไม่สำเร็จ: %s": "Connection failed: %s",
"รอการเชื่อมต่อ — ID %s": "Waiting for connections — ID %s",
"Server ปิดการเชื่อมต่อ": "The Server closed the connection",
"Server ตอบกลับไม่ถูกต้อง": "Unexpected reply from the Server",
"Server ปฏิเสธการเชื่อมต่อ": "The Server refused the connection",
"ยังไม่ได้ตั้งค่า Server — ไปที่แท็บ \"ตั้งค่า Server\"": "Server is not set up yet — go to the \"Server Settings\" tab",
"เชื่อมต่อกับเครื่องปลายทางไม่สำเร็จ — ลองใหม่อีกครั้ง": "Could not connect to the remote computer — please try again",
"เครื่องปลายทางไม่ได้ใช้โปรแกรม NetRemote": "The remote computer is not running NetRemote",
"ยกเลิกการเชื่อมต่อ — ยืนยันตัวตนของเครื่องปลายทางไม่ได้": "Connection cancelled — the remote computer could not be verified",
"โปรแกรมติดตั้งไม่สมบูรณ์ — กรุณาติดตั้งโปรแกรมใหม่ หรือติดต่อผู้ดูแลระบบ": "The program is not installed correctly — please reinstall it or contact your administrator",
"⚠ ข้อมูลยืนยันตัวตนของ %s (%s) เปลี่ยนไปจากที่เคยเชื่อมต่อ\n\nถ้าเครื่องปลายทางเพิ่งติดตั้งโปรแกรมใหม่ ถือว่าปกติ\nถ้าไม่ใช่ อาจมีผู้ไม่หวังดีพยายามดักข้อมูล\n\nต้องการเชื่อมต่อต่อหรือไม่?": "⚠ The identity of %s (%s) has changed since your last connection\n\nThis is normal if the program was just reinstalled on that computer.\nIf not, someone may be trying to intercept the connection.\n\nContinue connecting?",
"การเชื่อมต่อขัดข้อง": "Connection problem",
"หมดเวลาการเชื่อมต่อ — ตรวจสอบอินเทอร์เน็ต แล้วลองใหม่อีกครั้ง": "Connection timed out — check your internet and try again",
"เชื่อมต่อแบบปลอดภัยไม่สำเร็จ — ลองใหม่อีกครั้ง": "Could not establish a secure connection — please try again",
"ไม่พบ Server — ตรวจสอบที่อยู่ Server และอินเทอร์เน็ต": "Server not found — check the Server address and your internet",
"เชื่อมต่อ Server ไม่ได้ — ตรวจสอบอินเทอร์เน็ต หรือติดต่อผู้ดูแลระบบ": "Cannot reach the Server — check your internet or contact your administrator",
"พื้นที่ดิสก์เต็ม": "The disk is full",
"เกิดข้อผิดพลาด — ลองใหม่อีกครั้ง": "Something went wrong — please try again",
"เปิดไฟล์ติดตั้งให้แล้ว → ปิดโปรแกรมนี้ แล้วลาก NetRemote ไปไว้ใน Applications": "The installer has been opened → quit this program, then drag NetRemote into Applications",
"⬆ มีเวอร์ชันใหม่ %s — กำลังดาวน์โหลดอัตโนมัติ…": "⬆ New version %s — downloading automatically…",
"⬇  กำลังดาวน์โหลดอัปเดต %s": "⬇  Downloading update %s",
"✓ เวอร์ชัน %s พร้อมติดตั้ง — จะติดตั้งให้เมื่อปิดโปรแกรม": "✓ Version %s is ready — it will be installed when you close the program",
"↻  รีสตาร์ตและอัปเดตตอนนี้": "↻  Restart and update now",
"↻  รีสตาร์ตเพื่ออัปเดตเป็น %s": "↻  Restart to update to %s",
"⬆ ดาวน์โหลดเวอร์ชัน %s แล้ว — กดปุ่มด้านบนเพื่อรีสตาร์ต หรือจะติดตั้งให้เมื่อปิดโปรแกรม": "⬆ Version %s downloaded — click the button at the top to restart, or it will be installed when you close the program",
"รีสตาร์ตโปรแกรมเพื่ออัปเดตเป็นเวอร์ชัน %s ตอนนี้?": "Restart the program now to update to version %s?",
"การรีโมทที่เปิดอยู่จะถูกตัด": "Open remote sessions will be disconnected.",
"ติดตั้งอัปเดตไม่สำเร็จ: %s": "Could not install the update: %s",
"กำลังอัปเดตเป็นเวอร์ชัน %s …": "Updating to version %s …",
"ไฟล์ใหญ่เกิน 2 GB — ใช้ปุ่ม 📁 ไฟล์ แทน": "File is larger than 2 GB — use the 📁 Files button instead",
"ไฟล์ไม่สมบูรณ์": "The file is incomplete",
"อีกฝั่งยกเลิกการส่ง": "The other side cancelled the transfer",
"ไม่พบไมโครโฟนหรือลำโพงในเครื่องนี้": "No microphone or speaker found on this computer",
"เปิดไมโครโฟน/ลำโพงไม่ได้: %s": "Cannot open the microphone/speaker: %s",
"เปิดกล้องไม่ได้": "Cannot open the camera",
"เปิดกล้องไม่ได้: %s": "Cannot open the camera: %s",
"แชท": "Chat",
"เครื่องปลายทาง (%s) ใช้โปรแกรมเวอร์ชันเก่าที่ยังไม่มีแชท\n\nให้อัปเดตโปรแกรมบนเครื่องปลายทาง แล้วเชื่อมต่อใหม่": "The remote computer (%s) runs an older version without chat\n\nUpdate the program on the remote computer, then reconnect",
"รับสาย": "Answer",
"วางสาย": "Hang up",
"ยังไม่มีข้อความ\nพิมพ์ข้อความ หรือส่งไฟล์ รูป วีดีโอได้ที่ด้านล่าง": "No messages yet\nType a message, or send files, photos and videos below",
"รูป": "Photo",
"วีดีโอ": "Video",
"เลือกไฟล์ที่จะส่ง": "Choose files to send",
"เลือกรูปที่จะส่ง": "Choose photos to send",
"เลือกวีดีโอที่จะส่ง": "Choose videos to send",
"รูปภาพ": "Images",
"ทุกไฟล์": "All files",
"ส่งแล้ว ✓": "Sent ✓",
"ได้รับแล้ว ✓": "Received ✓",
"เปิด": "Open",
"แสดงในโฟลเดอร์": "Show in folder",
"ส่งไม่สำเร็จ": "Failed to send",
"ไม่พบไมโครโฟนหรือลำโพงในเครื่องนี้ จึงโทรไม่ได้": "No microphone or speaker found on this computer, so you can't call",
"ไม่พบกล้องในเครื่องนี้ — จะโทรด้วยเสียงอย่างเดียว": "No camera found on this computer — calling with voice only",
"วีดีโอคอลเข้า…": "Incoming video call…",
"สายเรียกเข้า…": "Incoming call…",
"วางสายแล้ว · %d:%02d": "Call ended · %d:%02d",
"อีกฝั่งไม่รับสาย": "No answer",
"อีกฝั่งสายไม่ว่าง": "The other side is busy",
"อีกฝั่งไม่มีไมโครโฟน/ลำโพง": "The other side has no microphone/speaker",
"ยกเลิกการโทร": "Call cancelled",
"กำลังโทรหา %s …": "Calling %s …",
"กำลังคุย": "On call"
}
_TH = {v: k for k, v in _EN.items()}


def srv(s):
    """ข้อความจาก Relay Server → ภาษาที่เลือก และเรียกว่า "Server" ให้ผู้ใช้"""
    return tr(s).replace("Relay Key", "Server Key").replace("Relay", "Server") if isinstance(s, str) else s


def tr(s):
    """แปลข้อความตามภาษาที่เลือก — รับได้ทั้งข้อความไทยและอังกฤษ (เช่นข้อความ error จากเครื่องอีกฝั่ง)"""
    if not isinstance(s, str):
        return s
    return _EN.get(s, s) if LANG == "en" else _TH.get(s, s)


T_HELLO, T_AUTH, T_OK, T_ERR = 1, 2, 3, 4
T_REQ, T_FRAME, T_INPUT, T_BYE = 10, 11, 20, 40
T_PING, T_PONG = 30, 31


def latency_style(ms):
    """คืน (ข้อความ, สี) ตามระดับ Latency"""
    if ms is None:
        return "—", "#888888"
    if ms < 30:
        return tr("ดีมาก"), "#1f9d55"
    if ms < 80:
        return tr("ดี"), "#1f9d55"
    if ms < 150:
        return tr("พอใช้"), "#d97706"
    return tr("ช้า"), "#dc2626"
HDR = struct.Struct("!BI")
MAX_MSG = 64 * 1024 * 1024

# คุณภาพภาพ: (ชื่อ, ความกว้างสูงสุด 0=เต็ม, JPEG quality, subsampling)
QUALITY = [(tr("ประหยัด"), 1280, 45, 2), (tr("ปกติ"), 1600, 60, 2), (tr("คมชัด"), 1920, 75, 1), (tr("สูงสุด"), 0, 88, 0)]

if SYSTEM == "Windows":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass


# ============================================================================
# ฟังก์ชันทั่วไป
# ============================================================================
def load_config():
    try:
        with open(CONF_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        os.makedirs(CONF_DIR, exist_ok=True)
        tmp = CONF_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=1)
        os.replace(tmp, CONF_FILE)
        try:
            os.chmod(CONF_FILE, 0o600)
        except OSError:
            pass
    except Exception:
        pass


def log_error(e):
    """บันทึก error ลง ~/.netremote/error.log (ช่วยหาสาเหตุเมื่อใช้แบบ .app / .exe)"""
    try:
        os.makedirs(CONF_DIR, exist_ok=True)
        with open(os.path.join(CONF_DIR, "error.log"), "a", encoding="utf-8") as f:
            f.write("%s  %s\n%s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), e,
                                     "".join(traceback.format_exception(type(e), e, e.__traceback__))))
    except Exception:
        pass


# ----------------------------------------------------------------------------
# เก็บรหัสผ่านที่ "จดจำ" ไว้อย่างปลอดภัย: macOS Keychain / Windows Credential Manager
# (ระบบอื่นหรือถ้าใช้ไม่ได้ → ไฟล์ ~/.netremote/secrets.json ที่อ่านได้เฉพาะผู้ใช้นี้)
# ----------------------------------------------------------------------------
SECRET_SERVICE = "NetRemote"
SECRET_STORE_NAME = {"Darwin": tr("Keychain ของ macOS"), "Windows": "Windows Credential Manager"}.get(
    SYSTEM, tr("ไฟล์ ~/.netremote (อ่านได้เฉพาะผู้ใช้นี้)"))
_SECRET_IDX = os.path.join(CONF_DIR, "saved_ids.json")
_SECRET_FILE = os.path.join(CONF_DIR, "secrets.json")
_secret_ids = None


def _json_load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _json_save(path, data):
    os.makedirs(CONF_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _ids():
    global _secret_ids
    if _secret_ids is None:
        _secret_ids = set(_json_load(_SECRET_IDX, []))
    return _secret_ids


def _win_cred(op, target, secret=None):
    import ctypes
    from ctypes import wintypes as wt

    class CRED(ctypes.Structure):
        _fields_ = [("Flags", wt.DWORD), ("Type", wt.DWORD), ("TargetName", wt.LPWSTR), ("Comment", wt.LPWSTR),
                    ("LastWritten", wt.FILETIME), ("CredentialBlobSize", wt.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_char)), ("Persist", wt.DWORD),
                    ("AttributeCount", wt.DWORD), ("Attributes", ctypes.c_void_p), ("TargetAlias", wt.LPWSTR),
                    ("UserName", wt.LPWSTR)]
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    if op == "set":
        blob = secret.encode("utf-16-le")
        buf = ctypes.create_string_buffer(blob, len(blob))
        c = CRED()
        c.Type, c.TargetName, c.UserName, c.Persist = 1, target, target, 2
        c.CredentialBlobSize = len(blob)
        c.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))
        return bool(adv.CredWriteW(ctypes.byref(c), 0))
    if op == "get":
        pc = ctypes.POINTER(CRED)()
        if not adv.CredReadW(target, 1, 0, ctypes.byref(pc)):
            return None
        try:
            c = pc.contents
            return ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize).decode("utf-16-le")
        finally:
            adv.CredFree(pc)
    return bool(adv.CredDeleteW(target, 1, 0))


def secret_has(rid):
    return bool(rid) and rid in _ids()


def secret_set(rid, pw):
    if not rid or not pw:
        return
    ok = False
    try:
        if SYSTEM == "Darwin":
            r = subprocess.run(["security", "add-generic-password", "-a", rid, "-s", SECRET_SERVICE,
                                "-l", "NetRemote %s" % rid, "-w", pw, "-U"], capture_output=True, timeout=10)
            ok = r.returncode == 0
        elif SYSTEM == "Windows":
            ok = _win_cred("set", "NetRemote:" + rid, pw)
    except Exception:
        ok = False
    if not ok:
        data = _json_load(_SECRET_FILE, {})
        data[rid] = base64.b64encode(pw.encode("utf-8")).decode()
        _json_save(_SECRET_FILE, data)
    _ids().add(rid)
    _json_save(_SECRET_IDX, sorted(_ids()))


def secret_get(rid):
    if not secret_has(rid):
        return ""
    try:
        if SYSTEM == "Darwin":
            r = subprocess.run(["security", "find-generic-password", "-a", rid, "-s", SECRET_SERVICE, "-w"],
                               capture_output=True, timeout=10)
            if r.returncode == 0:
                return r.stdout.decode("utf-8").rstrip("\n")
        elif SYSTEM == "Windows":
            v = _win_cred("get", "NetRemote:" + rid)
            if v:
                return v
    except Exception:
        pass
    v = _json_load(_SECRET_FILE, {}).get(rid)
    return base64.b64decode(v).decode("utf-8") if v else ""


def secret_del(rid):
    if not rid:
        return
    try:
        if SYSTEM == "Darwin":
            subprocess.run(["security", "delete-generic-password", "-a", rid, "-s", SECRET_SERVICE],
                           capture_output=True, timeout=10)
        elif SYSTEM == "Windows":
            _win_cred("del", "NetRemote:" + rid)
    except Exception:
        pass
    data = _json_load(_SECRET_FILE, {})
    if rid in data:
        del data[rid]
        _json_save(_SECRET_FILE, data)
    if rid in _ids():
        _ids().discard(rid)
        _json_save(_SECRET_IDX, sorted(_ids()))


def gen_password():
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    s = "".join(secrets.choice(alphabet) for _ in range(12))
    return "%s-%s-%s" % (s[:4], s[4:8], s[8:])


def norm_pw(pw):
    return (pw or "").replace("-", "").replace(" ", "").strip().lower()


def computer_name():
    if SYSTEM == "Darwin":
        try:
            out = subprocess.run(["scutil", "--get", "ComputerName"], capture_output=True, timeout=3)
            name = out.stdout.decode().strip()
            if name:
                return name
        except Exception:
            pass
    return platform.node() or socket.gethostname()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def direct_port():
    try:
        return max(0, min(65535, int(env_str("DIRECT_PORT", "0") or 0)))
    except ValueError:
        return 0


def get_local_ips():
    ips = [get_local_ip()]
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    return [ip for ip in ips if not ip.startswith("127.")] or ips


def fingerprint(der):
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, 32, 2))


def auth_mac(password, nonce, fp):
    return hmac.new(norm_pw(password).encode("utf-8"), nonce + b"|netremote|" + fp.encode(),
                    hashlib.sha256).hexdigest()


def jdump(o):
    return json.dumps(o, ensure_ascii=False).encode("utf-8")


def jload(b):
    return json.loads(b.decode("utf-8"))


def send_msg(sock, t, payload=b""):
    sock.sendall(HDR.pack(t, len(payload)) + payload)


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(tr("การเชื่อมต่อถูกปิด"))
        buf += chunk
    return bytes(buf)


def recv_msg(sock):
    t, n = HDR.unpack(recv_exact(sock, HDR.size))
    if n > MAX_MSG:
        raise ConnectionError(tr("การเชื่อมต่อขัดข้อง"))
    return t, recv_exact(sock, n)


def missing_modules(server):
    need = [("PIL", "Pillow")]
    if server:
        need += [("mss", "mss"), ("pynput", "pynput"), ("cryptography", "cryptography")]
    out = []
    for mod, pkg in need:
        try:
            __import__(mod)
        except ImportError:
            out.append(pkg)
        except Exception:
            pass   # import ได้แต่มีปัญหาอื่น (เช่น ไม่มีจอ) — แจ้งตอนใช้งานจริง
    return out


# ----------------------------------------------------------------------------
# Certificate (TLS)
# ----------------------------------------------------------------------------
def ensure_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    os.makedirs(CONF_DIR, exist_ok=True)
    name = "NetRemote %s" % computer_name()
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650))
                .sign(key, hashes.SHA256()))
        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except ImportError:
        r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                            "-subj", "/CN=NetRemote", "-keyout", KEY_FILE, "-out", CERT_FILE],
                           capture_output=True)
        if r.returncode != 0:
            raise RuntimeError(tr("โปรแกรมติดตั้งไม่สมบูรณ์ — กรุณาติดตั้งโปรแกรมใหม่ หรือติดต่อผู้ดูแลระบบ"))
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass


def server_fingerprint():
    with open(CERT_FILE, "rb") as f:
        der = ssl.PEM_cert_to_DER_cert(f.read().decode())
    return fingerprint(der)


def server_context():
    ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    return ctx


def client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE      # ตรวจด้วย fingerprint (TOFU) + HMAC ผูก fingerprint แทน
    return ctx


# ============================================================================
# Channel — ส่ง/รับข้อความบน TLS socket ด้วย thread เดียว (ปลอดภัยกับ SSL)
# ============================================================================
class Channel(threading.Thread):
    def __init__(self, sock, on_message, on_close, idle_timeout=25):
        super().__init__(daemon=True)
        self.sock = sock
        self.on_message, self.on_close = on_message, on_close
        self.out = deque()
        self.lock = threading.Lock()
        self.wr, self.ww = socket.socketpair()
        self.wr.setblocking(False)
        self.ww.setblocking(False)
        self.alive = True
        self.idle = idle_timeout
        self.last_rx = time.time()
        self.bytes_in = self.bytes_out = 0
        self.reason = ""
        self.qbytes = 0                      # ข้อมูลที่รอส่ง (ใช้ชะลอการส่งไฟล์ไม่ให้แย่งภาพ/เสียง)
        self.wlen = 0

    def send(self, t, payload=b""):
        if not self.alive:
            return False
        with self.lock:
            self.out.append(HDR.pack(t, len(payload)) + payload)
            self.qbytes += HDR.size + len(payload)
        self._wake()
        return True

    def backlog(self):
        return self.qbytes + self.wlen

    def _wake(self):
        try:
            self.ww.send(b"\0")
        except OSError:
            pass

    def close(self, reason=""):
        if self.alive:
            self.reason = self.reason or reason
            self.alive = False
            self._wake()

    def run(self):
        sock = self.sock
        sock.setblocking(False)
        rbuf, wbuf = bytearray(), b""
        try:
            while self.alive:
                if not wbuf:
                    with self.lock:
                        if self.out:
                            wbuf = b"".join(self.out)
                            self.out.clear()
                            self.qbytes = 0
                pend = sock.pending() if hasattr(sock, "pending") else 0
                try:
                    r, w, _ = select.select([sock, self.wr], [sock] if wbuf else [], [], 0 if pend else 0.5)
                except (OSError, ValueError):
                    break
                if self.wr in r:
                    try:
                        while self.wr.recv(4096):
                            pass
                    except (BlockingIOError, OSError):
                        pass
                if sock in r or pend:
                    try:
                        while True:
                            data = sock.recv(262144)
                            if not data:
                                self.reason = self.reason or tr("อีกฝั่งปิดการเชื่อมต่อ")
                                raise ConnectionError(self.reason)
                            rbuf += data
                            self.bytes_in += len(data)
                            self.last_rx = time.time()
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError, InterruptedError):
                        pass
                    while len(rbuf) >= HDR.size:
                        t, n = HDR.unpack_from(rbuf, 0)
                        if n > MAX_MSG:
                            raise ConnectionError(tr("การเชื่อมต่อขัดข้อง"))
                        if len(rbuf) < HDR.size + n:
                            break
                        payload = bytes(rbuf[HDR.size:HDR.size + n])
                        del rbuf[:HDR.size + n]
                        if t == T_BYE:
                            self.reason = self.reason or tr("อีกฝั่งตัดการเชื่อมต่อ")
                            raise ConnectionError(self.reason)
                        try:
                            self.on_message(t, payload)
                        except Exception:
                            traceback.print_exc()
                if wbuf:
                    try:
                        n = sock.send(wbuf[:262144])
                        wbuf = wbuf[n:]
                        self.bytes_out += n
                        self.wlen = len(wbuf)
                    except (ssl.SSLWantWriteError, ssl.SSLWantReadError, BlockingIOError, InterruptedError):
                        pass
                if self.idle and time.time() - self.last_rx > self.idle:
                    self.reason = self.reason or tr("ไม่ได้รับข้อมูลนานเกินไป (หมดเวลา)")
                    break
        except Exception as e:
            self.reason = self.reason or str(e) or e.__class__.__name__
        finally:
            self.alive = False
            if self.reason in ("", None):
                self.reason = tr("ตัดการเชื่อมต่อแล้ว")
            # พยายามบอกอีกฝั่งก่อนปิด
            try:
                sock.setblocking(True)
                sock.settimeout(0.5)
                sock.sendall(HDR.pack(T_BYE, 0))
            except Exception:
                pass
            for s in (sock, self.wr, self.ww):
                try:
                    s.close()
                except Exception:
                    pass
            try:
                self.on_close(self.reason)
            except Exception:
                traceback.print_exc()


# ============================================================================
# ฝั่งเครื่องที่ถูกควบคุม (Server)
# ============================================================================
def mac_permissions():
    """คืนค่า (บันทึกหน้าจอได้?, ควบคุมได้?) — None = ตรวจไม่ได้"""
    if SYSTEM != "Darwin":
        return None, None
    import ctypes
    scr = acc = None
    try:
        cg = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        cg.CGPreflightScreenCaptureAccess.restype = ctypes.c_bool
        scr = bool(cg.CGPreflightScreenCaptureAccess())
    except Exception:
        pass
    try:
        ap = ctypes.cdll.LoadLibrary(
            "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
        ap.AXIsProcessTrusted.restype = ctypes.c_bool
        acc = bool(ap.AXIsProcessTrusted())
    except Exception:
        pass
    return scr, acc


def mac_request_screen_access():
    try:
        import ctypes
        cg = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        cg.CGRequestScreenCaptureAccess.restype = ctypes.c_bool
        cg.CGRequestScreenCaptureAccess()
    except Exception:
        pass


def mac_open_settings(kind):
    pane = {"screen": "Privacy_ScreenCapture", "access": "Privacy_Accessibility"}[kind]
    subprocess.Popen(["open", "x-apple.systempreferences:com.apple.preference.security?" + pane])


class Capturer:
    """จับภาพหน้าจอ (ต้องสร้างและใช้ใน thread เดียวกัน)"""

    def __init__(self):
        import mss
        from PIL import Image
        self.Image = Image
        self.sct = (getattr(mss, "MSS", None) or mss.mss)()
        self.monitors = [dict(m) for m in self.sct.monitors[1:]] or [dict(self.sct.monitors[0])]
        self.use_screencapture = False

    def grab(self, idx):
        idx = max(0, min(idx, len(self.monitors) - 1))
        if not self.use_screencapture:
            try:
                s = self.sct.grab(self.monitors[idx])
                return self.Image.frombytes("RGB", s.size, s.bgra, "raw", "BGRX")
            except Exception:
                if SYSTEM != "Darwin":
                    raise
                self.use_screencapture = True
        path = os.path.join(CONF_DIR, "screen_tmp.jpg")
        subprocess.run(["screencapture", "-x", "-D", str(idx + 1), "-t", "jpg", path],
                       capture_output=True, timeout=10)
        img = self.Image.open(path)
        img.load()
        return img.convert("RGB")

    def close(self):
        try:
            self.sct.close()
        except Exception:
            pass


class Injector:
    """จำลองเมาส์/คีย์บอร์ดบนเครื่องนี้"""

    def __init__(self):
        from pynput.keyboard import Controller as KC, Key, KeyCode
        from pynput.mouse import Button, Controller as MC
        self.Key, self.KeyCode, self.Button = Key, KeyCode, Button
        self.kb, self.mouse = KC(), MC()
        self.held_keys = set()
        self.held_btns = []
        self.char_mods = {}
        self.pos = (0.0, 0.0)
        self.Q = None
        if SYSTEM == "Darwin":
            try:
                import Quartz
                self.Q = Quartz
                Q = Quartz
                self.QBTN = {
                    "left": (Q.kCGEventLeftMouseDown, Q.kCGEventLeftMouseUp, Q.kCGEventLeftMouseDragged,
                             Q.kCGMouseButtonLeft),
                    "right": (Q.kCGEventRightMouseDown, Q.kCGEventRightMouseUp, Q.kCGEventRightMouseDragged,
                              Q.kCGMouseButtonRight),
                    "middle": (Q.kCGEventOtherMouseDown, Q.kCGEventOtherMouseUp, Q.kCGEventOtherMouseDragged,
                               Q.kCGMouseButtonCenter),
                }
            except Exception:
                self.Q = None

    def _qpost(self, etype, btn, clicks=None):
        Q = self.Q
        ev = Q.CGEventCreateMouseEvent(None, etype, self.pos, btn)
        if clicks:
            Q.CGEventSetIntegerValueField(ev, Q.kCGMouseEventClickState, clicks)
        Q.CGEventPost(Q.kCGHIDEventTap, ev)

    def move(self, x, y):
        self.pos = (float(x), float(y))
        if self.Q:
            if self.held_btns:
                b = self.QBTN[self.held_btns[-1]]
                self._qpost(b[2], b[3])
            else:
                self._qpost(self.Q.kCGEventMouseMoved, 0)
        else:
            self.mouse.position = (int(round(x)), int(round(y)))

    def button(self, name, down, clicks=1):
        if name not in ("left", "right", "middle"):
            return
        if down and name not in self.held_btns:
            self.held_btns.append(name)
        elif not down and name in self.held_btns:
            self.held_btns.remove(name)
        if self.Q:
            b = self.QBTN[name]
            self._qpost(b[0] if down else b[1], b[3], max(1, min(int(clicks or 1), 3)))
        else:
            btn = getattr(self.Button, name)
            (self.mouse.press if down else self.mouse.release)(btn)

    def scroll(self, dx, dy):
        dx = max(-15, min(15, int(dx)))
        dy = max(-15, min(15, int(dy)))
        if dx or dy:
            self.mouse.scroll(dx, dy)

    def key(self, msg):
        down = bool(msg.get("d"))
        if "k" in msg:
            k = getattr(self.Key, str(msg["k"]), None)
            if k is None:
                return
            if down:
                self.kb.press(k)
                self.held_keys.add(k)
            else:
                self.kb.release(k)
                self.held_keys.discard(k)
            return
        c = str(msg.get("c", ""))[:1]
        if not c:
            return
        kc = self.KeyCode.from_char(c)
        if down:
            temp = []
            for m in msg.get("m", []):
                mk = getattr(self.Key, str(m), None)
                if mk is not None and mk not in self.held_keys and mk not in temp:
                    self.kb.press(mk)
                    temp.append(mk)
            self.kb.press(kc)
            self.char_mods.setdefault(c, []).extend(temp)
        else:
            self.kb.release(kc)
            for mk in reversed(self.char_mods.pop(c, [])):
                self.kb.release(mk)

    def type_text(self, s):
        self.release_all()
        if SYSTEM == "Linux":                     # X11 ต้องเว้นจังหวะเล็กน้อยสำหรับอักษรนอกแป้นพิมพ์
            for ch in s[:5000]:
                self.kb.type(ch)
                time.sleep(0.01)
        else:
            self.kb.type(s[:5000])

    def release_all(self):
        for name in list(self.held_btns):
            try:
                self.button(name, False)
            except Exception:
                pass
        for c, mods in list(self.char_mods.items()):
            for mk in mods:
                try:
                    self.kb.release(mk)
                except Exception:
                    pass
        self.char_mods.clear()
        for k in list(self.held_keys):
            try:
                self.kb.release(k)
            except Exception:
                pass
        self.held_keys.clear()

    def cursor(self):
        try:
            return self.mouse.position
        except Exception:
            return None


class Server(threading.Thread):
    """รอรับการเชื่อมต่อ ครั้งละ 1 เครื่อง
    events ที่ส่งออก: ("log", text) ("session", ip, name) ("session_end", ip, reason) ("server_err", text)"""

    def __init__(self, port, password, events, ask_cb=None, allow_control=True, allow_files=True, relay=None):
        super().__init__(daemon=True)
        self.port, self.password, self.events = port, password, events
        self.ask_cb = ask_cb
        self.allow_control = allow_control
        self.allow_files = allow_files
        self.relay = relay
        self.relay_thread = None
        self.stop_event = threading.Event()
        self.session = None
        self.session_lock = threading.Lock()
        self.fails = {}
        self.ctx = server_context()
        self.fp = server_fingerprint()
        self.lsock = None

    def log(self, text):
        self.events.put(("log", text))

    def stop(self):
        self.stop_event.set()
        if self.relay_thread:
            self.relay_thread.stop()
        try:
            self.lsock.close()
        except Exception:
            pass
        self.kick()

    def kick(self):
        s = self.session
        if s and s.get("chan"):
            s["chan"].close(tr("เครื่องปลายทางตัดการเชื่อมต่อ"))

    def run(self):
        # รับการเชื่อมต่อผ่าน Relay เท่านั้น — ไม่เปิดพอร์ตใด ๆ บนเครื่องนี้
        if not self.relay or not self.relay.get("addr"):
            self.events.put(("server_err", tr("ยังไม่ได้ตั้งค่า Server\n\nตั้งค่าที่แท็บ \"ตั้งค่า Server\"")))
            return
        r = self.relay
        if r.get("direct", True):
            UPNP.start()
        self.relay_thread = RelayHost(self, r["addr"], r.get("key", ""), r["id"], r["secret"], self.events)
        self.relay_thread.start()
        self.log(tr("พร้อมรับการเชื่อมต่อ — ID %s") % fmt_id(r["id"]))
        self.stop_event.wait()
        self.log(tr("ปิดการรับการเชื่อมต่อแล้ว"))

    # ----- per connection -----
    def _client(self, conn, addr):
        ip = addr[0]
        cnt, until = self.fails.get(ip, (0, 0))
        if time.time() < until:
            conn.close()
            return
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.settimeout(15)
        try:
            tls = self.ctx.wrap_socket(conn, server_side=True)
        except Exception:
            conn.close()                        # เช่น การสแกนพอร์ต
            return
        try:
            nonce = secrets.token_bytes(32)
            send_msg(tls, T_HELLO, jdump({"app": APP, "v": PROTO, "nonce": base64.b64encode(nonce).decode(),
                                          "name": computer_name()}))
            t, p = recv_msg(tls)
            if t != T_AUTH:
                raise ConnectionError(tr("การเชื่อมต่อขัดข้อง"))
            auth = jload(p)
            name = str(auth.get("name", ip))[:60]
            if not hmac.compare_digest(str(auth.get("mac", "")), auth_mac(self.password, nonce, self.fp)):
                cnt += 1
                self.fails[ip] = (cnt, time.time() + (60 if cnt >= 3 else 0))
                time.sleep(1.0)
                send_msg(tls, T_ERR, jdump({"msg": tr("รหัสผ่านไม่ถูกต้อง")}))
                self.log(tr("⚠ %s (%s) ใส่รหัสผ่านผิด%s") % (name, ip, tr(" — บล็อก 60 วินาที") if cnt >= 3 else ""))
                tls.close()
                return
            self.fails.pop(ip, None)
            with self.session_lock:
                busy = self.session is not None
            if busy:
                send_msg(tls, T_ERR, jdump({"msg": tr("เครื่องนี้มีผู้เชื่อมต่ออยู่แล้ว")}))
                tls.close()
                return
            if self.ask_cb:
                self.log(tr("%s (%s) ขอเชื่อมต่อ — รอการยืนยัน") % (name, ip))
                tls.settimeout(60)
                if not self.ask_cb(ip, name):
                    send_msg(tls, T_ERR, jdump({"msg": tr("เครื่องปลายทางปฏิเสธการเชื่อมต่อ")}))
                    self.log(tr("ปฏิเสธการเชื่อมต่อจาก %s (%s)") % (name, ip))
                    tls.close()
                    return
            with self.session_lock:
                if self.session is not None:
                    send_msg(tls, T_ERR, jdump({"msg": tr("เครื่องนี้มีผู้เชื่อมต่ออยู่แล้ว")}))
                    tls.close()
                    return
                self.session = {"ip": ip, "name": name}
        except Exception as e:
            try:
                tls.close()
            except Exception:
                pass
            if not isinstance(e, (ConnectionError, socket.timeout, ssl.SSLError)):
                self.log(tr("ผิดพลาด: %s") % err_text(e))
            return

        cap = inj = None
        try:
            cap = Capturer()
            try:
                inj = Injector()
            except Exception as e:
                self.log(tr("⚠ ควบคุมเมาส์/คีย์บอร์ดไม่ได้: %s") % err_text(e))
            mons = [{"w": m["width"], "h": m["height"]} for m in cap.monitors]
            send_msg(tls, T_OK, jdump({"name": computer_name(), "os": SYSTEM, "monitors": mons,
                                       "files": bool(self.allow_files), "v": PROTO, "chat": 1,
                                       "control": bool(self.allow_control and inj)}))
            self._session_loop(tls, ip, name, cap, inj)
        except Exception as e:
            self.log(tr("ผิดพลาดระหว่างเชื่อมต่อ: %s") % err_text(e))
            try:
                send_msg(tls, T_ERR, jdump({"msg": tr("เครื่องปลายทางผิดพลาด: %s") % err_text(e)}))
                tls.close()
            except Exception:
                pass
        finally:
            if inj:
                inj.release_all()
            if cap:
                cap.close()
            with self.session_lock:
                self.session = None

    def _session_loop(self, tls, ip, name, cap, inj):
        from PIL import ImageChops
        st = {"max_w": 1600, "q": 60, "sub": 2, "mon": 0, "force": True}
        req = threading.Event()
        closed = threading.Event()
        reason = {"r": ""}

        def on_message(t, p):
            if t in FILE_TYPES:
                fs.handle(t, p)
            elif t in CHAT_TYPES:
                chat.handle(t, p)
            elif t in CALL_TYPES:
                call.handle(t, p)
            elif t == T_REQ:
                d = jload(p)
                new = {"max_w": int(d.get("max_w", 1600)), "q": int(d.get("q", 60)),
                       "sub": int(d.get("sub", 2)), "mon": int(d.get("mon", 0))}
                for k, v in new.items():
                    if st.get(k) != v:
                        st[k] = v
                        st["force"] = True
                if d.get("full"):
                    st["force"] = True
                req.set()
            elif t == T_PING:
                chan.send(T_PONG, p)                 # ตอบกลับทันทีเพื่อให้อีกฝั่งวัด Latency
                try:
                    rtt = jload(p).get("rtt")
                    if rtt is not None:
                        self.events.put(("latency", ip, float(rtt)))
                except Exception:
                    pass
            elif t == T_INPUT and inj and self.allow_control:
                self._input(inj, cap, st["mon"], jload(p))

        def on_close(r):
            reason["r"] = r
            closed.set()
            req.set()

        chan = Channel(tls, on_message, on_close)
        fs = FileServer(chan, self.log, lambda: self.allow_files, "%s (%s)" % (name, ip))

        def deliver(ev):
            if ev.get("ev") == "call_incoming" and not getattr(self, "ui", True):
                call.decline("nodev")                # โหมดไม่มีหน้าต่าง: รับสายไม่ได้
                return
            self.events.put(("chat", ev))
        chat = ChatEngine(chan, deliver, name)
        call = CallEngine(chan, deliver)
        self.session["chan"] = chan
        self.session["chat"], self.session["call"] = chat, call
        self.events.put(("chat_open", chat, call, name))
        chan.start()
        self.events.put(("session", ip, name))
        self.log(tr("● %s (%s) เชื่อมต่อแล้ว") % (name, ip))
        prev = None
        last_sent = 0.0
        last_cur = None
        interval = 1.0 / 20
        while not closed.is_set() and not self.stop_event.is_set():
            if not req.wait(1.0):
                continue
            if closed.is_set():
                break
            wait = interval - (time.time() - last_sent)
            if wait > 0:
                time.sleep(wait)
            mon_i = max(0, min(st["mon"], len(cap.monitors) - 1))
            mon = cap.monitors[mon_i]
            img = cap.grab(mon_i)
            if st["max_w"] and img.width > st["max_w"]:
                img = img.resize((st["max_w"], max(1, round(img.height * st["max_w"] / img.width))),
                                 resample=4 if img.width > 2 * st["max_w"] else 2)
            w, h = img.size
            cur = None
            if inj:
                c = inj.cursor()
                if c:
                    cur = (round((c[0] - mon["left"]) / mon["width"], 4), round((c[1] - mon["top"]) / mon["height"], 4))
            force = st["force"] or prev is None or prev.size != img.size
            if force:
                bbox = (0, 0, w, h)
            else:
                bbox = ImageChops.difference(prev, img).getbbox()
            if bbox is None and cur == last_cur and time.time() - last_sent < 1.0:
                time.sleep(0.06)             # หน้าจอไม่เปลี่ยน — รอแล้วตรวจใหม่
                continue
            st["force"] = False
            req.clear()
            meta = {"fw": w, "fh": h, "x": 0, "y": 0, "w": 0, "h": 0}
            if cur:
                meta["cx"], meta["cy"] = cur
            data = b""
            if bbox:
                x0, y0 = bbox[0] // 16 * 16, bbox[1] // 16 * 16
                x1, y1 = min(w, -(-bbox[2] // 16) * 16), min(h, -(-bbox[3] // 16) * 16)
                if (x1 - x0) * (y1 - y0) > 0.55 * w * h:
                    x0, y0, x1, y1 = 0, 0, w, h
                buf = io.BytesIO()
                img.crop((x0, y0, x1, y1)).save(buf, "JPEG", quality=st["q"], subsampling=st["sub"])
                data = buf.getvalue()
                meta.update({"x": x0, "y": y0, "w": x1 - x0, "h": y1 - y0})
            js = jdump(meta)
            chan.send(T_FRAME, struct.pack("!H", len(js)) + js + data)
            prev = img
            last_sent = time.time()
            last_cur = cur
        fs.close()
        chat.close()
        call.close()
        self.events.put(("chat_end",))
        chan.close(tr("เครื่องนี้ตัดการเชื่อมต่อ") if self.stop_event.is_set() else "")
        chan.join(3)
        self.events.put(("session_end", ip, reason["r"] or chan.reason))
        self.log(tr("○ %s (%s) ออกจากการเชื่อมต่อ — %s") % (name, ip, reason["r"] or chan.reason))

    def _input(self, inj, cap, mon_i, m):
        try:
            mon = cap.monitors[max(0, min(mon_i, len(cap.monitors) - 1))]
            t = m.get("t")
            if t in ("move", "btn") and "x" in m:
                x = mon["left"] + max(0.0, min(1.0, float(m["x"]))) * (mon["width"] - 1)
                y = mon["top"] + max(0.0, min(1.0, float(m["y"]))) * (mon["height"] - 1)
                inj.move(x, y)
            if t == "btn":
                inj.button(m.get("b"), bool(m.get("d")), m.get("n", 1))
            elif t == "scroll":
                inj.scroll(m.get("dx", 0), m.get("dy", 0))
            elif t == "key":
                inj.key(m)
            elif t == "type":
                inj.type_text(str(m.get("s", "")))
            elif t == "release_all":
                inj.release_all()
        except Exception as e:
            self.log(tr("ควบคุมไม่สำเร็จ: %s") % err_text(e))


# ============================================================================
# รับ-ส่งไฟล์ (File Transfer)
# ============================================================================
T_FS, T_FS_R = 50, 51
T_UP_BEGIN, T_DATA, T_UP_END, T_ACK = 52, 53, 54, 55
T_XACK, T_XDONE, T_CANCEL = 56, 57, 58
T_DL_REQ, T_DL_FILE, T_DL_FEND = 59, 60, 61
FILE_TYPES = frozenset(range(50, 62))
XFER_CHUNK = 128 * 1024
XFER_WINDOW = 2 * 1024 * 1024
PART_EXT = ".netremote-part"


def fmt_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024
    return "%.1f TB" % n


def err_text(e):
    if isinstance(e, PermissionError):
        return tr("ไม่มีสิทธิ์เข้าถึง")
    if isinstance(e, FileNotFoundError):
        return tr("ไม่พบไฟล์หรือโฟลเดอร์")
    if isinstance(e, FileExistsError):
        return tr("มีชื่อนี้อยู่แล้ว")
    if isinstance(e, (socket.timeout, TimeoutError)):
        return tr("หมดเวลาการเชื่อมต่อ — ตรวจสอบอินเทอร์เน็ต แล้วลองใหม่อีกครั้ง")
    if isinstance(e, ssl.SSLError):
        return tr("เชื่อมต่อแบบปลอดภัยไม่สำเร็จ — ลองใหม่อีกครั้ง")
    if isinstance(e, socket.gaierror):
        return tr("ไม่พบ Server — ตรวจสอบที่อยู่ Server และอินเทอร์เน็ต")
    if isinstance(e, (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, BrokenPipeError)) or (
            isinstance(e, OSError) and e.errno in NET_ERRNOS):
        return tr("เชื่อมต่อ Server ไม่ได้ — ตรวจสอบอินเทอร์เน็ต หรือติดต่อผู้ดูแลระบบ")
    if isinstance(e, OSError) and e.strerror:
        sys.stderr.write("error: %r\n" % (e,))
        if e.errno == errno.ENOSPC:
            return tr("พื้นที่ดิสก์เต็ม")
        return tr("เกิดข้อผิดพลาด — ลองใหม่อีกครั้ง")
    text = str(e)
    if not text or re.search(r"Errno|Error\b|Exception|Traceback|object has no|[A-Za-z_]+\(", text):
        sys.stderr.write("error: %r\n" % (e,))
        return tr("เกิดข้อผิดพลาด — ลองใหม่อีกครั้ง")
    return text


NET_ERRNOS = {getattr(errno, n) for n in ("ECONNREFUSED", "ECONNRESET", "ECONNABORTED", "ENETUNREACH", "EHOSTUNREACH",
                                           "ENETDOWN", "EHOSTDOWN", "ETIMEDOUT", "EPIPE") if hasattr(errno, n)}


def safe_parts(rel):
    parts = [p for p in re.split(r"[\\/]+", str(rel)) if p not in ("", ".")]
    if not parts or any(p == ".." or ":" in p or "\0" in p for p in parts):
        raise ValueError(tr("ชื่อไฟล์ไม่ถูกต้อง: %s") % rel)
    return parts


def unique_path(path):
    if not os.path.exists(path) and not os.path.exists(path + PART_EXT):
        return path
    base, ext = os.path.splitext(path)
    i = 1
    while True:
        cand = "%s (%d)%s" % (base, i, ext)
        if not os.path.exists(cand) and not os.path.exists(cand + PART_EXT):
            return cand
        i += 1


def list_dir(path, hidden=False):
    if SYSTEM == "Windows" and not path and path is not None:
        drives = ["%s:\\" % c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists("%s:\\" % c)]
        return {"path": "", "parent": None,
                "entries": [{"n": d, "p": d, "d": True, "s": 0, "m": 0} for d in drives]}
    path = os.path.abspath(os.path.expanduser(path or "~"))
    entries = []
    with os.scandir(path) as it:
        for e in it:
            if e.name.endswith(PART_EXT) or (not hidden and e.name.startswith(".")):
                continue
            try:
                isdir = e.is_dir()
                st = e.stat()
            except OSError:
                continue
            entries.append({"n": e.name, "p": os.path.join(path, e.name), "d": isdir,
                            "s": 0 if isdir else st.st_size, "m": int(st.st_mtime)})
    entries.sort(key=lambda x: (not x["d"], x["n"].lower()))
    parent = os.path.dirname(path)
    if parent == path:
        parent = "" if SYSTEM == "Windows" else None
    return {"path": path, "parent": parent, "entries": entries[:10000]}


def delete_path(p):
    """ลบไฟล์/โฟลเดอร์ — บน macOS ย้ายไปถังขยะแทนการลบถาวร"""
    p = os.path.abspath(p)
    if not os.path.lexists(p):
        raise FileNotFoundError(p)
    if SYSTEM == "Darwin":
        trash = os.path.join(os.path.expanduser("~"), ".Trash")
        if os.path.isdir(trash):
            dest = unique_path(os.path.join(trash, os.path.basename(p.rstrip("/"))))
            shutil.move(p, dest)
            return
    if os.path.isdir(p) and not os.path.islink(p):
        shutil.rmtree(p)
    else:
        os.remove(p)


def expand_paths(paths):
    """แปลงรายการไฟล์/โฟลเดอร์ เป็น [(path, relpath, size)] (โฟลเดอร์ = ทุกไฟล์ข้างใน)"""
    out = []
    for p in paths:
        p = os.path.abspath(os.path.expanduser(p))
        if os.path.isdir(p):
            top = os.path.dirname(p.rstrip("\\/")) or p
            for root, dirs, files in os.walk(p):
                dirs.sort()
                for f in sorted(files):
                    if f.endswith(PART_EXT):
                        continue
                    fp = os.path.join(root, f)
                    try:
                        size = os.path.getsize(fp)
                    except OSError:
                        continue
                    out.append((fp, os.path.relpath(fp, top).replace(os.sep, "/"), size))
        elif os.path.isfile(p):
            out.append((p, os.path.basename(p), os.path.getsize(p)))
    return out


def open_path(p):
    try:
        if SYSTEM == "Darwin":
            subprocess.Popen(["open", p])
        elif SYSTEM == "Windows":
            os.startfile(p)
        else:
            subprocess.Popen(["xdg-open", p])
    except Exception:
        pass


class FileServer:
    """ฝั่งเครื่องที่ถูกควบคุม: ตอบคำขอดูไฟล์ / รับไฟล์อัปโหลด / ส่งไฟล์ให้ดาวน์โหลด"""

    def __init__(self, chan, log, allowed, who):
        self.chan, self.log, self.allowed, self.who = chan, log, allowed, who
        self.up = {}
        self.dl = {}

    def _send(self, t, obj):
        self.chan.send(t, jdump(obj))

    def handle(self, t, p):
        if t == T_DATA:
            self._up_data(struct.unpack_from("!I", p)[0], memoryview(p)[4:])
            return
        d = jload(p)
        tid = d.get("tid")
        if t == T_ACK:
            st = self.dl.get(tid)
            if st:
                with st["cond"]:
                    st["acked"] = int(d.get("n", 0))
                    st["cond"].notify_all()
            return
        if t == T_CANCEL:
            st = self.dl.get(tid)
            if st:
                with st["cond"]:
                    st["cancel"] = True
                    st["cond"].notify_all()
            self._up_discard(tid)
            return
        if not self.allowed():
            err = tr("เครื่องปลายทางไม่อนุญาตให้รับ-ส่งไฟล์")
            if t == T_FS:
                self._send(T_FS_R, {"id": d.get("id"), "ok": False, "err": err})
            elif t == T_UP_BEGIN:
                self._send(T_XACK, {"tid": tid, "ok": False, "err": err})
            elif t == T_DL_REQ:
                self._send(T_XDONE, {"tid": tid, "ok": False, "err": err})
            return
        if t == T_FS:
            self._fs(d)
        elif t == T_UP_BEGIN:
            self._up_begin(d)
        elif t == T_UP_END:
            self._up_end(d)
        elif t == T_DL_REQ:
            threading.Thread(target=self._download, args=(d,), daemon=True).start()

    def _fs(self, d):
        rid = d.get("id")
        try:
            if d.get("op") == "delete":
                errs = []
                for x in [str(v) for v in d.get("paths", [])][:500]:
                    try:
                        delete_path(x)
                    except Exception as e:
                        errs.append("%s: %s" % (os.path.basename(x), err_text(e)))
                self.log(tr("🗑 %s ลบ %d รายการ") % (self.who, len(d.get("paths", [])) - len(errs)))
                if errs:
                    raise RuntimeError(tr("ลบไม่สำเร็จบางรายการ — ") + "; ".join(errs[:5]))
            elif d.get("op") == "mkdir":
                parts = safe_parts(d.get("name", ""))
                if len(parts) != 1:
                    raise ValueError(tr("ชื่อโฟลเดอร์ไม่ถูกต้อง"))
                os.mkdir(os.path.join(os.path.abspath(d["path"]), parts[0]))
            res = list_dir(d.get("path"), bool(d.get("hidden")))
            res.update(id=rid, ok=True)
        except Exception as e:
            res = {"id": rid, "ok": False, "err": err_text(e), "path": d.get("path")}
        self._send(T_FS_R, res)

    def _up_begin(self, d):
        tid = d.get("tid")
        try:
            base = os.path.abspath(os.path.expanduser(str(d.get("dir") or "~")))
            if not os.path.isdir(base):
                raise ValueError(tr("ไม่พบโฟลเดอร์ปลายทาง"))
            final = os.path.join(base, *safe_parts(d.get("rel", "")))
            os.makedirs(os.path.dirname(final), exist_ok=True)
            final = unique_path(final)
            tmp = final + PART_EXT
            f = open(tmp, "wb")
        except Exception as e:
            self._send(T_XACK, {"tid": tid, "ok": False, "err": err_text(e)})
            return
        st = self.up.setdefault(tid, {"got": 0, "f": None, "count": 0, "bytes": 0})
        if st["f"]:
            self._up_discard(tid, keep_state=True)
        st.update(f=f, tmp=tmp, final=final)
        self._send(T_XACK, {"tid": tid, "ok": True, "path": final})

    def _up_data(self, tid, data):
        st = self.up.get(tid)
        if not st or not st.get("f"):
            return
        try:
            st["f"].write(data)
        except OSError as e:
            self._up_discard(tid)
            self._send(T_XDONE, {"tid": tid, "ok": False, "err": err_text(e)})
            return
        st["got"] += len(data)
        st["bytes"] += len(data)
        self._send(T_ACK, {"tid": tid, "n": st["got"]})

    def _up_end(self, d):
        tid = d.get("tid")
        st = self.up.get(tid)
        if not st or not st.get("f"):
            self._send(T_XDONE, {"tid": tid, "ok": False, "err": tr("ไม่พบการอัปโหลดนี้")})
            return
        try:
            st["f"].close()
            st["f"] = None
            os.replace(st["tmp"], st["final"])
            st["count"] += 1
            self._send(T_XDONE, {"tid": tid, "ok": True, "path": st["final"]})
            self.log(tr("⬆ ได้รับไฟล์ %s (%s) จาก %s") % (os.path.basename(st["final"]),
                                                     fmt_size(os.path.getsize(st["final"])), self.who))
        except OSError as e:
            self._up_discard(tid)
            self._send(T_XDONE, {"tid": tid, "ok": False, "err": err_text(e)})

    def _up_discard(self, tid, keep_state=False):
        st = self.up.get(tid) if keep_state else self.up.pop(tid, None)
        if st and st.get("f"):
            try:
                st["f"].close()
                os.remove(st["tmp"])
            except OSError:
                pass
            st["f"] = None

    def _download(self, d):
        tid = d.get("tid")
        st = {"acked": 0, "cancel": False, "cond": threading.Condition()}
        self.dl[tid] = st
        try:
            paths = [str(x) for x in d.get("paths", [])][:1000]
            files = expand_paths(paths)
            if not files and any(not os.path.exists(x) for x in paths):
                raise FileNotFoundError()
            total = sum(s for _, _, s in files)
            sent = 0
            for i, (fp, rel, size) in enumerate(files):
                if st["cancel"] or not self.chan.alive:
                    return
                with open(fp, "rb") as f:
                    self._send(T_DL_FILE, {"tid": tid, "rel": rel, "size": size, "idx": i,
                                           "count": len(files), "total": total})
                    while True:
                        with st["cond"]:
                            while sent - st["acked"] > XFER_WINDOW and not st["cancel"] and self.chan.alive:
                                st["cond"].wait(0.5)
                        if st["cancel"] or not self.chan.alive:
                            return
                        chunk = f.read(XFER_CHUNK)
                        if not chunk:
                            break
                        self.chan.send(T_DATA, struct.pack("!I", tid) + chunk)
                        sent += len(chunk)
                self._send(T_DL_FEND, {"tid": tid})
            self._send(T_XDONE, {"tid": tid, "ok": True, "count": len(files), "total": total})
            if files:
                self.log(tr("⬇ ส่งไฟล์ %d ไฟล์ (%s) ให้ %s") % (len(files), fmt_size(total), self.who))
        except Exception as e:
            self._send(T_XDONE, {"tid": tid, "ok": False, "err": err_text(e)})
        finally:
            self.dl.pop(tid, None)

    def close(self):
        for st in list(self.dl.values()):
            st["cancel"] = True
        for tid in list(self.up):
            self._up_discard(tid)


class FileClient:
    """ฝั่งเครื่องที่ควบคุม: ขอรายการไฟล์ / อัปโหลด / ดาวน์โหลด"""

    def __init__(self, chan):
        self.chan = chan
        self.events = queue.Queue()
        self.lock = threading.Lock()
        self.rid = 0
        self.tid = 0
        self.jobs = {}

    # ----- file browser -----
    def _fs(self, op, **kw):
        with self.lock:
            self.rid += 1
            rid = self.rid
        kw.update(op=op, id=rid)
        self.chan.send(T_FS, jdump(kw))
        return rid

    def list(self, path=None, hidden=False):
        return self._fs("list", path=path, hidden=hidden)

    def mkdir(self, path, name, hidden=False):
        return self._fs("mkdir", path=path, name=name, hidden=hidden)

    # ----- jobs -----
    def _new_job(self, direction, name, dest):
        with self.lock:
            self.tid += 1
            tid = self.tid
        job = {"tid": tid, "dir": direction, "name": name, "dest": dest, "total": 0, "done": 0,
               "acked": 0, "count": 0, "idx": 0, "status": tr("กำลังเริ่ม…"), "state": "active",
               "cancel": False, "failed": None, "files": [], "t0": time.time(), "t1": None,
               "cond": threading.Condition(), "ev": threading.Event(), "reply": None,
               "flock": threading.Lock(), "f": None}
        self.jobs[tid] = job
        return job

    @staticmethod
    def progress(job):
        return job["acked"] if job["dir"] == "up" else job["done"]

    def _label(self, paths):
        name = os.path.basename(str(paths[0]).rstrip("\\/")) or str(paths[0])
        return name + (tr(" และอีก %d รายการ") % (len(paths) - 1) if len(paths) > 1 else "")

    def upload(self, local_paths, remote_dir):
        job = self._new_job("up", self._label(local_paths), remote_dir)
        threading.Thread(target=self._upload_worker, args=(job, list(local_paths)), daemon=True).start()
        return job

    def _wait_reply(self, job, timeout=30):
        ok = job["ev"].wait(timeout)
        job["ev"].clear()
        r, job["reply"] = job["reply"], None
        if job["cancel"]:
            raise InterruptedError()
        if not ok or r is None:
            raise ConnectionError(tr("ปลายทางไม่ตอบสนอง"))
        if not r.get("ok"):
            raise ConnectionError(srv(r.get("err")) or tr("ผิดพลาด"))
        return r

    def _upload_worker(self, job, local_paths):
        tid = job["tid"]
        sent = 0
        try:
            files = expand_paths(local_paths)
            if not files:
                raise ValueError(tr("ไม่มีไฟล์ให้ส่ง"))
            job.update(total=sum(s for _, _, s in files), count=len(files))
            for i, (lp, rel, size) in enumerate(files):
                job.update(idx=i + 1, status=tr("กำลังส่ง %d/%d  %s") % (i + 1, len(files), rel))
                self.chan.send(T_UP_BEGIN, jdump({"tid": tid, "dir": job["dest"], "rel": rel, "size": size}))
                self._wait_reply(job)
                with open(lp, "rb") as f:
                    while True:
                        with job["cond"]:
                            while (sent - job["acked"] > XFER_WINDOW and not job["cancel"]
                                   and not job["failed"] and self.chan.alive):
                                job["cond"].wait(0.5)
                        if job["cancel"]:
                            raise InterruptedError()
                        if job["failed"]:
                            raise ConnectionError(job["failed"])
                        if not self.chan.alive:
                            raise ConnectionError(tr("การเชื่อมต่อถูกตัด"))
                        chunk = f.read(XFER_CHUNK)
                        if not chunk:
                            break
                        self.chan.send(T_DATA, struct.pack("!I", tid) + chunk)
                        sent += len(chunk)
                self.chan.send(T_UP_END, jdump({"tid": tid}))
                r = self._wait_reply(job, 120)
                job["files"].append(r.get("path", ""))
            self._finish(job, True)
        except InterruptedError:
            pass
        except Exception as e:
            self._finish(job, False, err_text(e))

    def download(self, remote_paths, local_dir):
        job = self._new_job("down", self._label(remote_paths), local_dir)
        job["status"] = tr("กำลังเตรียมไฟล์…")
        self.chan.send(T_DL_REQ, jdump({"tid": job["tid"], "paths": list(remote_paths)}))
        return job

    def _dl_open(self, job, d):
        with job["flock"]:
            self._dl_close_locked(job)
            final = os.path.join(job["dest"], *safe_parts(d.get("rel", "")))
            os.makedirs(os.path.dirname(final), exist_ok=True)
            final = unique_path(final)
            job["tmp"], job["final"] = final + PART_EXT, final
            job["f"] = open(job["tmp"], "wb")
            job.update(total=int(d.get("total", 0)), count=int(d.get("count", 0)), idx=int(d.get("idx", 0)) + 1,
                       status=tr("กำลังรับ %d/%d  %s") % (int(d.get("idx", 0)) + 1, int(d.get("count", 0)),
                                                      d.get("rel", "")))

    def _dl_close_locked(self, job, discard=False):
        f = job.get("f")
        if f is None:
            return
        job["f"] = None
        try:
            f.close()
            if discard:
                os.remove(job["tmp"])
            else:
                os.replace(job["tmp"], job["final"])
                job["files"].append(job["final"])
        except OSError:
            pass

    def handle(self, t, p):
        if t == T_DATA:
            tid = struct.unpack_from("!I", p)[0]
            job = self.jobs.get(tid)
            if not job or job["dir"] != "down" or job["state"] != "active":
                return
            try:
                with job["flock"]:
                    if job["f"] is None:
                        return
                    job["f"].write(memoryview(p)[4:])
                job["done"] += len(p) - 4
                self.chan.send(T_ACK, jdump({"tid": tid, "n": job["done"]}))
            except OSError as e:
                self.cancel(tid, err_text(e))
            return
        d = jload(p)
        if t == T_FS_R:
            self.events.put(("fs", d))
            return
        job = self.jobs.get(d.get("tid"))
        if not job:
            return
        if t == T_ACK:
            with job["cond"]:
                job["acked"] = int(d.get("n", 0))
                job["cond"].notify_all()
        elif job["dir"] == "up" and t in (T_XACK, T_XDONE):
            if not d.get("ok"):
                with job["cond"]:
                    job["failed"] = tr(d.get("err")) or tr("ผิดพลาด")
                    job["cond"].notify_all()
            job["reply"] = d
            job["ev"].set()
        elif job["dir"] == "down" and job["state"] == "active":
            if t == T_DL_FILE:
                try:
                    self._dl_open(job, d)
                except Exception as e:
                    self.cancel(job["tid"], err_text(e))
            elif t == T_DL_FEND:
                with job["flock"]:
                    self._dl_close_locked(job)
            elif t == T_XDONE:
                with job["flock"]:
                    self._dl_close_locked(job, discard=not d.get("ok"))
                if not d.get("ok"):
                    self._finish(job, False, tr(d.get("err")) or tr("ผิดพลาด"))
                elif not d.get("count"):
                    self._finish(job, False, tr("ไม่มีไฟล์ (โฟลเดอร์ว่าง)"))
                else:
                    job["total"] = int(d.get("total", job["total"]))
                    self._finish(job, True)

    def _finish(self, job, ok, err=""):
        if job["state"] != "active":
            return
        job["t1"] = time.time()
        if ok:
            job["state"] = "done"
            job["status"] = tr("✓ เสร็จ (%d ไฟล์)") % len(job["files"])
        else:
            job["state"] = "cancelled" if job["cancel"] else "error"
            job["status"] = (tr("ยกเลิกแล้ว") if job["cancel"] and not err else "✗ " + err)
        self.events.put(("job_done", job["tid"]))

    def cancel(self, tid, err=""):
        job = self.jobs.get(tid)
        if not job or job["state"] != "active":
            return
        job["cancel"] = True
        with job["cond"]:
            job["cond"].notify_all()
        job["ev"].set()
        self.chan.send(T_CANCEL, jdump({"tid": tid}))
        with job["flock"]:
            self._dl_close_locked(job, discard=True)
        self._finish(job, False, err)

    def close(self):
        for tid, job in list(self.jobs.items()):
            if job["state"] == "active":
                job["cancel"] = True
                with job["cond"]:
                    job["cond"].notify_all()
                job["ev"].set()
                with job["flock"]:
                    self._dl_close_locked(job, discard=True)
                self._finish(job, False, tr("การเชื่อมต่อถูกตัด"))


# ============================================================================
# เชื่อมต่อผ่านอินเทอร์เน็ต (Relay)
# ============================================================================
RELAY_PORT = 5910
ID_RE = re.compile(r"^\s*(\d{3})[\s-]?(\d{3})[\s-]?(\d{3})\s*$")


def parse_id(s):
    m = ID_RE.match(s or "")
    return "".join(m.groups()) if m else None


def fmt_id(i):
    i = str(i or "")
    return "%s %s %s" % (i[:3], i[3:6], i[6:9]) if len(i) == 9 else i


def new_host_id():
    return str(100000000 + secrets.randbelow(900000000))


def parse_hostport(s, default):
    s = (s or "").strip()
    if not s:
        raise ValueError(tr("ยังไม่ได้ตั้งค่า Server"))
    if s.startswith("["):
        h, _, rest = s[1:].partition("]")
        p = rest.lstrip(":")
    elif s.count(":") == 1:
        h, p = s.split(":")
    else:
        h, p = s, ""
    return h.strip(), int(p) if p.strip() else default


def line_send(sock, obj):
    sock.sendall(json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n")


def line_recv(sock, limit=8192):
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError(tr("Server ปิดการเชื่อมต่อ"))
        if b == b"\n":
            return json.loads(buf.decode("utf-8"))
        buf += b
        if len(buf) > limit:
            raise ConnectionError(tr("Server ตอบกลับไม่ถูกต้อง"))


def _relay_socket(addr, timeout=10):
    h, p = parse_hostport(addr, RELAY_PORT)
    s = socket.create_connection((h, p), timeout=timeout)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return s


# ============================================================================
# แชท + ส่งไฟล์/รูป/วีดีโอ + โทรเสียง/วีดีโอคอล (ระหว่างผู้ควบคุมกับเครื่องปลายทาง)
# วิ่งในช่องเดียวกับภาพหน้าจอ (เข้ารหัส TLS) — ถ้าเชื่อมต่อแบบ P2P ก็ไม่ผ่าน Server
# ============================================================================
T_CHAT = 70
T_CF_BEGIN, T_CF_DATA, T_CF_END, T_CF_CANCEL = 71, 72, 73, 74
T_CALL, T_AUDIO, T_VIDEO = 80, 81, 82
T_CHAT_META = 75                     # กำลังพิมพ์ / อ่านแล้ว (เวอร์ชันเก่าไม่รู้จัก → ไม่สนใจ)
CHAT_TYPES = {T_CHAT, T_CF_BEGIN, T_CF_DATA, T_CF_END, T_CF_CANCEL, T_CHAT_META}
CALL_TYPES = {T_CALL, T_AUDIO, T_VIDEO}
CHAT_MAX_FILE = 2 * 1024 ** 3
IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".heic", ".tif", ".tiff")
VIDEO_EXT = (".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm", ".wmv", ".3gp")
AUDIO_RATE, AUDIO_BLOCK = 16000, 320                 # 16 kHz mono 16-bit, ช่วงละ 20 ms


def chat_dir():
    base = env_str("DOWNLOAD_DIR", "") or os.path.join(os.path.expanduser("~"), "Downloads")
    return os.path.join(os.path.expanduser(base), "NetRemote Chat")


def file_kind(name):
    n = name.lower()
    return "image" if n.endswith(IMAGE_EXT) else ("video" if n.endswith(VIDEO_EXT) else "file")


def media_available():
    """(ไมค์/ลำโพงใช้ได้?, กล้องใช้ได้?) — ตรวจครั้งเดียวแล้วจำไว้"""
    global _MEDIA
    try:
        return _MEDIA
    except NameError:
        pass
    audio = video = False
    try:
        import sounddevice as sd
        devs = sd.query_devices()
        audio = any(d.get("max_input_channels", 0) > 0 for d in devs) and \
            any(d.get("max_output_channels", 0) > 0 for d in devs)
    except Exception:
        audio = False
    try:
        import cv2  # noqa: F401
        video = True
    except Exception:
        video = False
    _MEDIA = (audio, video)
    return _MEDIA


def open_camera():
    """เปิดกล้องตัวแรก — Windows ลอง DirectShow ก่อน (ค่าเริ่มต้นของ OpenCV มักเปิดกล้อง USB ไม่ได้) แล้วค่อย MSMF"""
    import cv2
    if SYSTEM == "Windows":
        apis = [getattr(cv2, "CAP_DSHOW", 700), getattr(cv2, "CAP_MSMF", 1400), None]
    elif SYSTEM == "Darwin":
        apis = [getattr(cv2, "CAP_AVFOUNDATION", 1200), None]
    else:
        apis = [None]
    for api in apis:
        for idx in (0, 1):
            try:
                cap = cv2.VideoCapture(idx) if api is None else cv2.VideoCapture(idx, api)
            except Exception:
                continue
            if cap.isOpened():
                ok, _f = cap.read()
                if ok:
                    try:
                        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                    except Exception:
                        pass
                    return cap
            cap.release()
    return None


class ChatEngine:
    """ส่ง/รับข้อความและไฟล์ในแชท — ไม่มี UI; ส่งเหตุการณ์ออกทาง deliver(dict) (เรียกจาก thread อื่น)"""

    def __init__(self, chan, deliver, peer=""):
        self.chan, self.deliver, self.peer = chan, deliver, peer
        self.rx = {}
        self.cancelled = set()
        self.lock = threading.Lock()
        self.closed = False
        self.last_typing = 0

    def _id(self):
        return secrets.token_hex(6)

    def send_text(self, text):
        text = str(text).strip()
        if not text:
            return None
        m = {"id": self._id(), "text": text[:8000], "t": time.time(), "name": computer_name()}
        self.chan.send(T_CHAT, jdump(m))
        self.deliver(dict(m, ev="msg", mine=True))
        return m["id"]

    def send_typing(self):
        now = time.time()
        if now - self.last_typing > 2.5 and self.chan.alive:
            self.last_typing = now
            self.chan.send(T_CHAT_META, jdump({"op": "typing"}))

    def send_read(self, ids):
        ids = [str(i) for i in ids if i][:200]
        if ids and self.chan.alive:
            self.chan.send(T_CHAT_META, jdump({"op": "read", "ids": ids}))

    def send_file(self, path):
        try:
            size = os.path.getsize(path)
        except OSError as e:
            self.deliver({"ev": "error", "text": err_text(e)})
            return None
        if size > CHAT_MAX_FILE:
            self.deliver({"ev": "error", "text": tr("ไฟล์ใหญ่เกิน 2 GB — ใช้ปุ่ม 📁 ไฟล์ แทน")})
            return None
        fid = self._id()
        name = os.path.basename(path)
        meta = {"id": fid, "name": name, "size": size, "kind": file_kind(name), "t": time.time(),
                "name_from": computer_name()}
        self.deliver(dict(meta, ev="file", mine=True, path=path, done=0, status="sending"))
        threading.Thread(target=self._send_worker, args=(path, meta), daemon=True).start()
        return fid

    def cancel(self, fid):
        self.cancelled.add(fid)
        self.chan.send(T_CF_CANCEL, jdump({"id": fid}))

    def _send_worker(self, path, meta):
        fid = meta["id"]
        bid = bytes.fromhex(fid)
        sha = hashlib.sha256()
        sent = 0
        try:
            self.chan.send(T_CF_BEGIN, jdump(meta))
            with open(path, "rb") as f:
                last = 0
                while True:
                    if fid in self.cancelled or not self.chan.alive:
                        raise InterruptedError(tr("ยกเลิกแล้ว"))
                    while self.chan.backlog() > 1024 * 1024 and self.chan.alive:   # ไม่ให้ไฟล์แย่งช่องภาพ/เสียง
                        time.sleep(0.01)
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sha.update(chunk)
                    self.chan.send(T_CF_DATA, bid + chunk)
                    sent += len(chunk)
                    if time.time() - last > 0.2:
                        last = time.time()
                        self.deliver({"ev": "progress", "id": fid, "done": sent, "size": meta["size"]})
            self.chan.send(T_CF_END, jdump({"id": fid, "sha256": sha.hexdigest()}))
            self.deliver({"ev": "progress", "id": fid, "done": sent, "size": meta["size"], "status": "sent"})
        except Exception as e:
            self.deliver({"ev": "progress", "id": fid, "done": sent, "size": meta["size"], "status": "failed",
                          "text": err_text(e) if not isinstance(e, InterruptedError) else tr("ยกเลิกแล้ว")})

    def handle(self, t, p):
        if t == T_CHAT_META:
            m = jload(p)
            if m.get("op") == "typing":
                self.deliver({"ev": "typing"})
            elif m.get("op") == "read":
                self.deliver({"ev": "read", "ids": [str(i) for i in (m.get("ids") or [])]})
        elif t == T_CHAT:
            m = jload(p)
            self.deliver(dict(m, ev="msg", mine=False))
        elif t == T_CF_BEGIN:
            m = jload(p)
            fid = str(m.get("id", ""))
            d = chat_dir()
            os.makedirs(d, exist_ok=True)
            path = unique_path(os.path.join(d, os.path.basename(str(m.get("name", "file"))) or "file"))
            try:
                fh = open(path + PART_EXT, "wb")
            except OSError as e:
                self.deliver({"ev": "error", "text": err_text(e)})
                return
            with self.lock:
                self.rx[fid] = {"fh": fh, "path": path, "sha": hashlib.sha256(), "got": 0, "meta": m, "last": 0}
            self.deliver(dict(m, ev="file", mine=False, path=path, done=0, status="receiving"))
        elif t == T_CF_DATA:
            fid = p[:6].hex()
            r = self.rx.get(fid)
            if not r:
                return
            r["fh"].write(p[6:])
            r["sha"].update(p[6:])
            r["got"] += len(p) - 6
            if time.time() - r["last"] > 0.2:
                r["last"] = time.time()
                self.deliver({"ev": "progress", "id": fid, "done": r["got"], "size": r["meta"].get("size", 0)})
        elif t == T_CF_END:
            m = jload(p)
            fid = str(m.get("id", ""))
            with self.lock:
                r = self.rx.pop(fid, None)
            if not r:
                return
            r["fh"].close()
            ok = r["sha"].hexdigest() == m.get("sha256")
            if ok:
                os.replace(r["path"] + PART_EXT, r["path"])
            else:
                try:
                    os.remove(r["path"] + PART_EXT)
                except OSError:
                    pass
            self.deliver({"ev": "progress", "id": fid, "done": r["got"], "size": r["meta"].get("size", 0),
                          "status": "received" if ok else "failed", "path": r["path"],
                          "text": "" if ok else tr("ไฟล์ไม่สมบูรณ์")})
        elif t == T_CF_CANCEL:
            fid = str(jload(p).get("id", ""))
            self.cancelled.add(fid)
            with self.lock:
                r = self.rx.pop(fid, None)
            if r:
                r["fh"].close()
                try:
                    os.remove(r["path"] + PART_EXT)
                except OSError:
                    pass
            self.deliver({"ev": "progress", "id": fid, "status": "failed", "text": tr("อีกฝั่งยกเลิกการส่ง")})

    def close(self):
        self.closed = True
        with self.lock:
            rx, self.rx = self.rx, {}
        for r in rx.values():
            try:
                r["fh"].close()
                os.remove(r["path"] + PART_EXT)
            except OSError:
                pass


class CallEngine:
    """โทรเสียง / วีดีโอคอล — สัญญาณ (invite/accept/decline/end) + สตรีมเสียง PCM และภาพ JPEG
    ส่งเหตุการณ์ทาง deliver(dict): call_incoming, call_state, remote_video, self_video, call_error"""

    def __init__(self, chan, deliver):
        self.chan, self.deliver = chan, deliver
        self.state = "idle"                  # idle / calling / ringing / active
        self.video = False                   # เปิดกล้องฝั่งเรา
        self.muted = False
        self.speaker_off = False
        self.started = 0
        self.lock = threading.Lock()
        self.play = bytearray()
        self.play_ready = False
        self.in_stream = self.out_stream = None
        self.cam_stop = threading.Event()
        self.peer_video = False
        self.sid = None

    # ----- สัญญาณ -----
    def _sig(self, op, **kw):
        kw.update(op=op, sid=self.sid)
        self.chan.send(T_CALL, jdump(kw))

    def start_call(self, video):
        if self.state != "idle":
            return
        audio_ok, video_ok = media_available()
        if not audio_ok:
            self.deliver({"ev": "call_error", "text": tr("ไม่พบไมโครโฟนหรือลำโพงในเครื่องนี้")})
            return
        self.sid = secrets.token_hex(4)
        self.video = bool(video and video_ok)
        self._set("calling")
        self._sig("invite", video=self.video)

    def accept(self, video=False):
        if self.state != "ringing":
            return
        audio_ok, video_ok = media_available()
        if not audio_ok:
            self.deliver({"ev": "call_error", "text": tr("ไม่พบไมโครโฟนหรือลำโพงในเครื่องนี้")})
            self.decline("nodev")
            return
        self.video = bool(video and video_ok)
        self._sig("accept", video=self.video)
        self._begin()

    def decline(self, reason="declined"):
        if self.state in ("ringing", "calling"):
            self._sig("decline", reason=reason)
        self._finish(reason)

    def hangup(self):
        if self.state != "idle":
            self._sig("end")
        self._finish("ended")

    def set_mute(self, on):
        self.muted = bool(on)

    def set_video(self, on):
        on = bool(on) and media_available()[1]
        if on == self.video:
            return
        self.video = on
        if self.state == "active":
            self._sig("video", on=on)
            if on:
                self._start_camera()
            else:
                self.cam_stop.set()
                self.deliver({"ev": "self_video", "jpg": None})

    def handle(self, t, p):
        if t == T_AUDIO:
            if self.state == "active":
                with self.lock:
                    self.play += p
                    cap = AUDIO_RATE * 2 * 0.4             # เก็บไม่เกิน 0.4 วินาที กันเสียงดีเลย์สะสม
                    if len(self.play) > cap:
                        del self.play[:len(self.play) - int(AUDIO_RATE * 2 * 0.12)]
            return
        if t == T_VIDEO:
            if self.state == "active":
                self.deliver({"ev": "remote_video", "jpg": p})
            return
        m = jload(p)
        op = m.get("op")
        if op == "invite":
            if self.state != "idle":
                self.chan.send(T_CALL, jdump({"op": "decline", "sid": m.get("sid"), "reason": "busy"}))
                return
            self.sid = m.get("sid")
            self.peer_video = bool(m.get("video"))
            self._set("ringing")
            self.deliver({"ev": "call_incoming", "video": self.peer_video, "name": m.get("name", "")})
        elif m.get("sid") != self.sid:
            return
        elif op == "accept" and self.state == "calling":
            self.peer_video = bool(m.get("video"))
            self._begin()
        elif op == "decline":
            self._finish(m.get("reason") or "declined")
        elif op == "end":
            self._finish("ended")
        elif op == "video":
            self.peer_video = bool(m.get("on"))
            if not self.peer_video:
                self.deliver({"ev": "remote_video", "jpg": None})
            self.deliver({"ev": "call_state", "state": self.state, "peer_video": self.peer_video})

    def _set(self, state):
        self.state = state
        self.deliver({"ev": "call_state", "state": state, "video": self.video, "peer_video": self.peer_video,
                      "started": self.started})

    # ----- สื่อ -----
    def _begin(self):
        self.started = time.time()
        with self.lock:
            self.play = bytearray()
            self.play_ready = False
        try:
            self._start_audio()
        except Exception as e:
            self.deliver({"ev": "call_error", "text": tr("เปิดไมโครโฟน/ลำโพงไม่ได้: %s") % err_text(e)})
            self.hangup()
            return
        self._set("active")
        if self.video:
            self._start_camera()

    def _start_audio(self):
        import sounddevice as sd

        def mic(indata, frames, ti, status):
            if self.state == "active" and not self.muted and self.chan.alive:
                self.chan.send(T_AUDIO, bytes(indata))

        def spk(outdata, frames, ti, status):
            need = frames * 2
            with self.lock:
                if not self.play_ready and len(self.play) >= AUDIO_RATE * 2 * 0.06:
                    self.play_ready = True             # รอเก็บเสียงไว้ 60 ms ก่อนเริ่มเล่น ลดเสียงสะดุด
                if self.play_ready and len(self.play) >= need:
                    outdata[:] = bytes(self.play[:need]) if not self.speaker_off else b"\0" * need
                    del self.play[:need]
                    return
                got = bytes(self.play) if self.play_ready else b""
                self.play = bytearray()
                self.play_ready = False
            outdata[:] = got + b"\0" * (need - len(got))

        self.in_stream = sd.RawInputStream(samplerate=AUDIO_RATE, channels=1, dtype="int16",
                                           blocksize=AUDIO_BLOCK, callback=mic)
        self.out_stream = sd.RawOutputStream(samplerate=AUDIO_RATE, channels=1, dtype="int16",
                                             blocksize=AUDIO_BLOCK, callback=spk)
        self.in_stream.start()
        self.out_stream.start()

    def _start_camera(self):
        self.cam_stop = threading.Event()
        threading.Thread(target=self._camera_loop, args=(self.cam_stop,), daemon=True).start()

    def _camera_loop(self, stop):
        try:
            import cv2
            cap = open_camera()
        except Exception:
            cap = None
        if cap is None:
            self.deliver({"ev": "call_error", "text": tr("เปิดกล้องไม่ได้ — ไม่พบกล้อง หรือกล้องถูกโปรแกรมอื่นใช้อยู่")})
            self.video = False
            self._sig("video", on=False)
            return
        try:
            last_prev = 0
            while not stop.is_set() and self.state == "active" and self.video and self.chan.alive:
                t0 = time.time()
                ok, frame = cap.read()
                if not ok:
                    time.sleep(0.05)
                    continue
                h, w = frame.shape[:2]
                if w > 480:
                    frame = cv2.resize(frame, (480, int(h * 480 / w)), interpolation=cv2.INTER_AREA)
                ok, jpg = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), 62])
                if ok:
                    data = jpg.tobytes()
                    if self.chan.backlog() < 384 * 1024:            # เน็ตช้า: ข้ามภาพ แต่เสียงยังไป
                        self.chan.send(T_VIDEO, data)
                    if time.time() - last_prev > 0.1:
                        last_prev = time.time()
                        self.deliver({"ev": "self_video", "jpg": data})
                time.sleep(max(0.0, 1 / 15 - (time.time() - t0)))
        finally:
            cap.release()

    def _finish(self, reason):
        was = self.state
        self.state = "idle"
        self.cam_stop.set()
        for s in (self.in_stream, self.out_stream):
            try:
                if s:
                    s.stop()
                    s.close()
            except Exception:
                pass
        self.in_stream = self.out_stream = None
        dur = time.time() - self.started if self.started and was == "active" else 0
        self.started = 0
        self.deliver({"ev": "call_state", "state": "idle", "reason": reason, "was": was, "duration": dur})

    def close(self):
        if self.state != "idle":
            self._finish("ended")


# ============================================================================
# เชื่อมต่อตรงแบบ P2P (ไม่ผ่าน Server) — ลองทุกทางพร้อมกัน:
#   • ทั้งสองทิศทาง: เครื่องที่ควบคุม → ปลายทาง และ ปลายทาง → เครื่องที่ควบคุม (กัน Firewall ฝั่งใดฝั่งหนึ่ง)
#   • IPv4 วง LAN, IPv6 (ข้ามอินเทอร์เน็ตได้ถ้ามี), และพอร์ตที่เปิดอัตโนมัติผ่าน UPnP ของ Router
# ทุกช่องต้องยืนยันด้วย token ครั้งเดียวจาก Server แล้วยังต้องผ่าน TLS + รหัสผ่านเหมือนเดิม
# เครื่องที่ควบคุมเป็นผู้ "เลือก" ช่องที่ใช้ (pick) — จึงได้ช่องเดียวเสมอแม้ต่อสำเร็จหลายทาง
# ============================================================================
P2P_PROTO = 2


def _private_v4(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return True


def get_local_ip6():
    """IPv6 ที่ออกอินเทอร์เน็ตได้ (global) ของเครื่องนี้ — ไม่ส่งข้อมูลจริง"""
    s = None
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect(("2001:4860:4860::8888", 53))
        ip = s.getsockname()[0].split("%")[0]
        a = ipaddress.ip_address(ip)
        return ip if a.is_global else None
    except Exception:
        return None
    finally:
        if s:
            s.close()


class Upnp:
    """เปิดพอร์ตชั่วคราวที่ Router อัตโนมัติ (UPnP IGD) — ถ้า Router ไม่รองรับก็ข้ามไปเงียบ ๆ"""
    ST = ("urn:schemas-upnp-org:service:WANIPConnection:1", "urn:schemas-upnp-org:service:WANIPConnection:2",
          "urn:schemas-upnp-org:service:WANPPPConnection:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:1")

    def __init__(self):
        self.ctrl = self.stype = self.ext_ip = None
        self.done = threading.Event()
        self.lock = threading.Lock()

    def start(self):
        if not self.done.is_set() and not getattr(self, "_started", False):
            self._started = True
            threading.Thread(target=self._discover, daemon=True).start()

    def _discover(self):
        try:
            import urllib.request
            import xml.etree.ElementTree as ET
            from urllib.parse import urljoin
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            for st in self.ST:
                s.sendto(("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                          "MX: 1\r\nST: %s\r\n\r\n" % st).encode(), ("239.255.255.250", 1900))
            locs = []
            t_end = time.time() + 2.0
            while time.time() < t_end:
                try:
                    data, _a = s.recvfrom(4096)
                except socket.timeout:
                    break
                m = re.search(rb"(?im)^location:\s*(\S+)", data)
                if m and m.group(1).decode() not in locs:
                    locs.append(m.group(1).decode())
            s.close()
            for loc in locs:
                try:
                    xml = urllib.request.urlopen(loc, timeout=2).read()
                    root = ET.fromstring(xml)
                    base = loc
                    for el in root.iter():
                        if el.tag.endswith("URLBase") and el.text:
                            base = el.text.strip()
                    for svc in root.iter():
                        if not svc.tag.endswith("service"):
                            continue
                        st = ct = None
                        for c in svc:
                            if c.tag.endswith("serviceType"):
                                st = (c.text or "").strip()
                            elif c.tag.endswith("controlURL"):
                                ct = (c.text or "").strip()
                        if st and ct and ("WANIPConnection" in st or "WANPPPConnection" in st):
                            self.ctrl, self.stype = urljoin(base, ct), st
                            ip = self._soap("GetExternalIPAddress", {}).get("NewExternalIPAddress")
                            self.ext_ip = ip if ip and not _private_v4(ip) else None
                            return
                except Exception:
                    continue
        except Exception:
            pass
        finally:
            self.done.set()

    def _soap(self, action, args):
        import urllib.request
        body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%s xmlns:u="%s">%s</u:%s>'
                '</s:Body></s:Envelope>') % (action, self.stype,
                                             "".join("<%s>%s</%s>" % (k, v, k) for k, v in args.items()), action)
        req = urllib.request.Request(self.ctrl, data=body.encode(), headers={
            "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": '"%s#%s"' % (self.stype, action)})
        out = urllib.request.urlopen(req, timeout=2).read().decode("utf-8", "replace")
        return dict(re.findall(r"<(New\w+)>([^<]*)</New\w+>", out))

    def map(self, port, wait=1.0):
        """เปิดพอร์ต TCP ภายนอก → พอร์ตนี้ของเครื่องเรา คืน "ip:port" หรือ None"""
        self.done.wait(wait)
        if not (self.ctrl and self.ext_ip):
            return None
        local = get_local_ip()
        for lease in (300, 0):
            try:
                self._soap("AddPortMapping", {
                    "NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": "TCP", "NewInternalPort": port,
                    "NewInternalClient": local, "NewEnabled": 1, "NewPortMappingDescription": "NetRemote",
                    "NewLeaseDuration": lease})
                threading.Timer(25, self.unmap, args=(port,)).start()      # ปิดพอร์ตหลังหมดเวลาเชื่อมต่อ
                return "%s:%d" % (self.ext_ip, port)
            except Exception:
                continue
        return None

    def unmap(self, port):
        try:
            self._soap("DeletePortMapping", {"NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": "TCP"})
        except Exception:
            pass


UPNP = Upnp()


def p2p_listen(fixed_port=0):
    """เปิดพอร์ตชั่วคราวรับการเชื่อมต่อตรง (IPv4 + IPv6) — คืน (socket, port) หรือ (None, 0)"""
    for fam in (socket.AF_INET6, socket.AF_INET):
        for p in ([fixed_port, 0] if fixed_port else [0]):
            ls = None
            try:
                ls = socket.socket(fam, socket.SOCK_STREAM)
                ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if fam == socket.AF_INET6:
                    ls.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    ls.bind(("::", p))
                else:
                    ls.bind(("0.0.0.0", p))
                ls.listen(8)
                return ls, ls.getsockname()[1]
            except Exception:
                if ls:
                    ls.close()
    return None, 0


def p2p_cands(ls, port):
    """ที่อยู่ที่อีกฝั่งลองเชื่อมต่อเข้ามาได้ — LAN, IPv6, และพอร์ตที่เปิดผ่าน UPnP"""
    out = ["%s:%d" % (ip, port) for ip in get_local_ips() if not ip.startswith("127.")]
    if ls is not None and ls.family == socket.AF_INET6:
        ip6 = get_local_ip6()
        if ip6:
            out.append("[%s]:%d" % (ip6, port))
    up = UPNP.map(port)
    if up and up not in out:
        out.append(up)
    return out[:10]


def _p2p_connect(c, timeout):
    h, p = parse_hostport(c, 0)
    return socket.create_connection((h, p), timeout=timeout)


def p2p_race(token, peer_cands, ls, i_pick, timeout=3.5, legacy=False):
    """ลองต่อตรงทุกทางพร้อมกัน คืน (socket, รายละเอียด)
    i_pick=True  = เครื่องที่ควบคุม (เป็นผู้เลือกช่อง)
    i_pick=False = เครื่องปลายทาง (รอให้อีกฝั่งเลือก)
    legacy=True  = อีกฝั่งเป็นโปรแกรมเวอร์ชันเก่า (ต่อออกทางเดียว ไม่มีขั้นตอน pick)"""
    won, lock, done = {}, threading.Lock(), threading.Event()
    deadline = time.time() + timeout
    tried = list(peer_cands)

    def finish(sock, how):
        with lock:
            if "s" in won:
                return False
            won["s"], won["how"] = sock, how
        done.set()
        return True

    def handshake(sock, outbound, how):
        """ยืนยัน token แล้วตกลงเลือกช่อง — คืน True ถ้าช่องนี้ถูกเลือก"""
        sock.settimeout(max(1.0, deadline - time.time() + 1.5))
        if outbound:
            line_send(sock, {"token": token, "p2p": P2P_PROTO})
            r = line_recv(sock, 1024)
            if not r.get("ok"):
                return False
            if legacy:
                return finish(sock, how)
            if i_pick:
                with lock:
                    if "s" in won:
                        return False
                    won["s"], won["how"] = sock, how
                line_send(sock, {"pick": 1})
                done.set()
                return True
            return bool(r.get("pick")) and finish(sock, how)
        r = line_recv(sock, 1024)
        if not hmac.compare_digest(str(r.get("token", "")), token):
            return False
        if legacy or int(r.get("p2p") or 0) < P2P_PROTO:     # อีกฝั่งเวอร์ชันเก่า: ไม่มีขั้นตอน pick
            with lock:
                if "s" in won:
                    return False
            line_send(sock, {"ok": True})
            return finish(sock, how)
        if i_pick:
            with lock:
                if "s" in won:
                    return False
                won["s"], won["how"] = sock, how
            line_send(sock, {"ok": True, "pick": 1})
            done.set()
            return True
        line_send(sock, {"ok": True})
        return bool(line_recv(sock, 1024).get("pick")) and finish(sock, how)

    def dial(c):
        sock = None
        try:
            sock = _p2p_connect(c, min(2.5, max(0.5, deadline - time.time())))
            if handshake(sock, True, "out " + c):
                sock = None
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def accept_loop():
        while not done.is_set() and time.time() < deadline:
            try:
                ls.settimeout(max(0.1, min(0.5, deadline - time.time())))
                conn, addr = ls.accept()
            except (socket.timeout, OSError):
                continue

            def serve(conn=conn, addr=addr):
                try:
                    if handshake(conn, False, "in " + str(addr[0])):
                        return
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
            threading.Thread(target=serve, daemon=True).start()

    if ls is not None:
        threading.Thread(target=accept_loop, daemon=True).start()
    for c in peer_cands:
        threading.Thread(target=dial, args=(c,), daemon=True).start()
    if peer_cands or ls is not None:
        done.wait(max(0.1, deadline - time.time()))
    with lock:
        s = won.get("s")
        how = won.get("how", "")
        won.setdefault("s", None)
    if s is not None:
        s.settimeout(None)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        return s, how
    why = "tried %s" % ", ".join(tried[:6]) if tried else "no address"
    return None, why


def relay_dial(addr, key, host_id, direct=True):
    """เครื่องที่ควบคุม: ขอเชื่อมต่อไปยัง ID ผ่าน Server
    ลองเชื่อมต่อตรง (P2P) ก่อนเสมอ ต่อไม่ได้จึงให้ Server ส่งต่อข้อมูล
    คืน (socket, route, presence) — route = "direct" / "relay", presence = ช่องที่เปิดค้างกับ Server (หรือ None)"""
    ls, port = p2p_listen() if direct else (None, 0)
    s = None
    try:
        my_cands = p2p_cands(ls, port) if ls is not None else []
        s = _relay_socket(addr)
        s.settimeout(25)
        line_send(s, {"role": "client", "id": host_id, "key": key or "", "v": 1, "lang": LANG,
                      "direct": 1 if direct else 0, "p2p": P2P_PROTO if direct else 0, "ccands": my_cands})
        r = line_recv(s)
        if not r.get("ok"):
            raise ConnectionError(srv(r.get("err")) or tr("Server ปฏิเสธการเชื่อมต่อ"))
        if r.get("phase") == "direct":
            legacy = int(r.get("hp2p") or 0) < P2P_PROTO
            ds, how = p2p_race(str(r.get("token", "")), [str(c) for c in r.get("cands") or []],
                               None if legacy else ls, True, legacy=legacy)
            if ds is not None:
                line_send(s, {"use": "direct", "how": how})
                return ds, "direct", s
            line_send(s, {"use": "relay", "why": how, "mine": my_cands})
            r = line_recv(s)
            if not r.get("ok"):
                raise ConnectionError(srv(r.get("err")) or tr("Server ปฏิเสธการเชื่อมต่อ"))
        return s, "relay", None
    except Exception:
        if s is not None:
            s.close()
        raise
    finally:
        if ls is not None:
            try:
                ls.close()
            except Exception:
                pass


def relay_test(addr, key):
    s = _relay_socket(addr)
    try:
        s.settimeout(10)
        t0 = time.monotonic()
        line_send(s, {"role": "ping", "key": key or "", "v": 1, "lang": LANG})
        r = line_recv(s)
        r["rtt"] = (time.monotonic() - t0) * 1000
        if not r.get("ok"):
            raise ConnectionError(srv(r.get("err")) or tr("Server ปฏิเสธการเชื่อมต่อ"))
        return r
    finally:
        s.close()


# ----------------------------------------------------------------------------
# ตรวจสอบ / ดาวน์โหลดอัปเดตโปรแกรมจาก Server
# ----------------------------------------------------------------------------
def version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v or ""))[:4]) or (0,)


def update_platform():
    if SYSTEM == "Darwin":
        return "mac-" + ("arm64" if platform.machine() in ("arm64", "aarch64") else "x86_64")
    return "windows" if SYSTEM == "Windows" else "linux"


UPDATE_DIR = os.path.join(CONF_DIR, "updates")


def relaunch_self(cmd):
    """เปิดโปรแกรมตัวเองใหม่ — ล้างตัวแปรของ PyInstaller onefile ไม่ให้ตัวใหม่ไปใช้โฟลเดอร์ชั่วคราวของตัวเก่า"""
    env = {k: v for k, v in os.environ.items() if not (k.startswith("_MEI") or k.startswith("_PYI"))}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    kw = {}
    if SYSTEM == "Windows":
        kw["creationflags"] = 0x00000200 | 0x00000008          # NEW_PROCESS_GROUP | DETACHED_PROCESS
    else:
        kw["start_new_session"] = True
    try:
        subprocess.Popen(cmd, close_fds=True, env=env, **kw)
    except Exception:
        pass


def cleanup_old_exe():
    """ลบไฟล์ .exe ตัวเก่าที่เหลือจากการอัปเดตครั้งก่อน"""
    if SYSTEM != "Windows" or not getattr(sys, "frozen", False):
        return
    exe = os.path.abspath(sys.executable)
    for f in glob.glob(glob.escape(exe) + ".old*"):
        for _ in range(10):
            try:
                os.remove(f)
                break
            except OSError:
                time.sleep(0.5)


def install_target():
    """โปรแกรมที่จะถูกแทนที่ตอนอัปเดตอัตโนมัติ — (ชนิด, path) หรือ (None, None) ถ้าติดตั้งเองไม่ได้"""
    if getattr(sys, "frozen", False):
        exe = os.path.abspath(sys.executable)
        if SYSTEM == "Darwin" and ".app/Contents/MacOS" in exe:
            return "mac-app", exe.split(".app/Contents/MacOS")[0] + ".app"
        if SYSTEM == "Windows":
            return "win-exe", exe
        return None, None
    return "source", os.path.abspath(__file__)


def update_plat_for(info):
    """แพลตฟอร์มของไฟล์ที่จะขอจาก Server — รันจาก source ใช้ไฟล์ .py ("source") ถ้ามี"""
    kind, _t = install_target()
    files = (info or {}).get("files") or {}
    if kind == "source" and "source" in files:
        return "source"
    return update_platform()


def can_auto_install(info):
    kind, target = install_target()
    plat = update_plat_for(info)
    f = ((info or {}).get("files") or {}).get(plat)
    if not kind or not f:
        return False
    name = f["name"].lower()
    ok_ext = {"mac-app": (".dmg", ".zip"), "win-exe": (".exe",), "source": (".py",)}[kind]
    if not name.endswith(ok_ext):
        return False
    return os.access(os.path.dirname(target) or ".", os.W_OK) and (not os.path.exists(target) or
                                                                    os.access(target, os.W_OK))


def launch_installer(pkg, relaunch=True):
    """ติดตั้งไฟล์อัปเดตหลังโปรแกรมนี้ปิด (สคริปต์แยกรอจนโปรแกรมปิด แล้วแทนที่ไฟล์ + เปิดใหม่)"""
    kind, target = install_target()
    pid = os.getpid()
    if kind == "source":
        tmp = target + ".new"
        shutil.copyfile(pkg, tmp)
        os.replace(tmp, target)
        if relaunch:
            RESTART.append(True)
        return True
    if kind == "win-exe":
        # Windows ยอมให้ "เปลี่ยนชื่อ" ไฟล์ .exe ที่กำลังทำงานอยู่ได้ → ย้ายตัวเก่าออก วางตัวใหม่แทน
        # แล้วเปิดใหม่ตอนปิดโปรแกรม (ไม่ต้องใช้สคริปต์ .bat / หน้าต่าง Command)
        old = target + ".old"
        try:
            if os.path.exists(old):
                os.remove(old)
        except OSError:
            old = target + ".old%d" % pid
        try:
            os.replace(target, old)
        except OSError as e:
            raise OSError(tr("ไม่มีสิทธิ์เขียนไฟล์ในโฟลเดอร์ของโปรแกรม — ย้ายโปรแกรมไปไว้ที่โฟลเดอร์อื่น (เช่น Desktop) แล้วลองใหม่")) from e
        try:
            shutil.copyfile(pkg, target)
        except BaseException:
            try:
                os.replace(old, target)
            except OSError:
                pass
            raise
        try:
            os.remove(pkg)
        except OSError:
            pass
        if relaunch:
            RESTART.append(True)
        return True
    if kind == "mac-app":
        sh = os.path.join(UPDATE_DIR, "install_%d.sh" % pid)
        q = lambda p: "'" + p.replace("'", "'\\''") + "'"
        with open(sh, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n"
                    "while kill -0 %d 2>/dev/null; do sleep 0.5; done\n"
                    "PKG=%s; TARGET=%s; WORK=$(mktemp -d /tmp/netremote-update.XXXXXX)\n"
                    'if [[ "$PKG" == *.dmg ]]; then\n'
                    '  hdiutil attach -nobrowse -noverify -noautoopen -mountpoint "$WORK/mnt" "$PKG" >/dev/null || exit 1\n'
                    '  SRC=$(ls -d "$WORK"/mnt/*.app | head -1)\n'
                    "else\n"
                    '  ditto -x -k "$PKG" "$WORK/zip" || exit 1\n'
                    '  SRC=$(ls -d "$WORK"/zip/*.app "$WORK"/zip/*/*.app 2>/dev/null | head -1)\n'
                    "fi\n"
                    'if [ -n "$SRC" ] && ditto "$SRC" "$TARGET.new"; then\n'
                    '  rm -rf "$TARGET.old"; mv "$TARGET" "$TARGET.old" && mv "$TARGET.new" "$TARGET" && rm -rf "$TARGET.old"\n'
                    '  xattr -dr com.apple.quarantine "$TARGET" 2>/dev/null\n'
                    "fi\n"
                    '[[ "$PKG" == *.dmg ]] && hdiutil detach "$WORK/mnt" -quiet\n'
                    'rm -rf "$WORK" "$PKG"\n'
                    "%s"
                    'rm -f "$0"\n' % (pid, q(pkg), q(target), 'open "$TARGET"\n' if relaunch else ""))
        os.chmod(sh, 0o700)
        subprocess.Popen(["/bin/bash", sh], start_new_session=True, close_fds=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    return False


def relay_update_info(addr, key):
    s = _relay_socket(addr)
    try:
        s.settimeout(20)
        line_send(s, {"role": "update_info", "key": key or "", "v": 1, "lang": LANG})
        r = line_recv(s, limit=65536)
        if not r.get("ok"):
            raise ConnectionError(srv(r.get("err")) or tr("Server ปฏิเสธการเชื่อมต่อ"))
        return r
    finally:
        s.close()


def relay_update_download(addr, key, plat, dest_dir, progress=None, cancel=None):
    """ดาวน์โหลดไฟล์อัปเดตผ่าน Server แล้วตรวจ SHA-256 — คืน path ของไฟล์"""
    s = _relay_socket(addr)
    try:
        s.settimeout(60)
        line_send(s, {"role": "update_get", "key": key or "", "plat": plat, "v": 1})
        h = line_recv(s, limit=65536)
        if not h.get("ok"):
            raise ConnectionError(srv(h.get("err")) or tr("Server ปฏิเสธการเชื่อมต่อ"))
        size, name = int(h["size"]), os.path.basename(h["name"])
        os.makedirs(dest_dir, exist_ok=True)
        final = unique_path(os.path.join(dest_dir, name))
        tmp = final + PART_EXT
        sha = hashlib.sha256()
        got = 0
        try:
            with open(tmp, "wb") as f:
                while got < size:
                    if cancel and cancel.is_set():
                        raise InterruptedError(tr("ยกเลิกแล้ว"))
                    chunk = s.recv(min(262144, size - got))
                    if not chunk:
                        raise ConnectionError(tr("การดาวน์โหลดถูกตัดกลางทาง"))
                    f.write(chunk)
                    sha.update(chunk)
                    got += len(chunk)
                    if progress:
                        progress(got, size)
            if sha.hexdigest() != h.get("sha256"):
                raise ValueError(tr("ไฟล์ที่ดาวน์โหลดไม่สมบูรณ์ — ลองดาวน์โหลดใหม่"))
            os.replace(tmp, final)
            return final
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
    finally:
        s.close()


class RelayMonitor(threading.Thread):
    """ตรวจสถานะการเชื่อมต่อกับ Relay เป็นระยะ ส่งผล ("relay_status", state, data) ทาง queue"""

    def __init__(self, get_conn, out_q):
        super().__init__(daemon=True)
        self.get_conn, self.q = get_conn, out_q
        self.wake = threading.Event()

    def refresh(self):
        self.wake.set()

    def run(self):
        while True:
            addr, key = self.get_conn()
            ok = False
            if not addr:
                self.q.put(("relay_status", "unset", None))
            else:
                self.q.put(("relay_status", "checking", addr))
                try:
                    r = relay_test(addr, key)
                    r["addr"] = addr
                    ok = True
                    self.q.put(("relay_status", "ok", r))
                except Exception as e:
                    self.q.put(("relay_status", "error", "%s" % err_text(e)))
            self.wake.wait(10 if ok else 5)
            self.wake.clear()


class RelayHost(threading.Thread):
    """เครื่องที่ถูกควบคุม: ลงทะเบียน ID กับ Relay และรอรับการเชื่อมต่อจากอินเทอร์เน็ต"""

    def __init__(self, server, addr, key, host_id, secret, events):
        super().__init__(daemon=True)
        self.server, self.addr, self.key = server, addr, key or ""
        self.host_id, self.secret, self.events = host_id, secret, events
        self.stop_event = threading.Event()
        self.sock = None
        self.send_lock = threading.Lock()
        self.direct = {}                          # token -> listening socket ที่รอการเชื่อมต่อตรง

    def _ctl(self, obj):
        with self.send_lock:
            line_send(self.sock, obj)

    def status(self, state, text):
        self.events.put(("relay", state, text))

    def stop(self):
        self.stop_event.set()
        try:
            self.sock.close()
        except Exception:
            pass

    def run(self):
        backoff = 3
        while not self.stop_event.is_set():
            self.status("connecting", tr("กำลังเชื่อมต่อ Server …"))
            wait = backoff
            try:
                s = _relay_socket(self.addr)
                self.sock = s
                s.settimeout(15)
                line_send(s, {"role": "host", "id": self.host_id, "secret": self.secret, "key": self.key, "app": VERSION, "lang": LANG,
                              "name": computer_name(), "v": 1})
                r = line_recv(s)
                if not r.get("ok"):
                    self.status("error", srv(r.get("err")) or tr("Server ปฏิเสธการเชื่อมต่อ"))
                    wait = 60
                    raise ConnectionError("")
                self.status("online", tr("ออนไลน์ — พร้อมรับการเชื่อมต่อ"))
                self.server.log(tr("เชื่อมต่อ Server แล้ว — ID %s") % fmt_id(self.host_id))
                backoff = 3
                s.settimeout(1.0)
                buf, last_ping, last_rx = b"", time.time(), time.time()
                while not self.stop_event.is_set():
                    now = time.time()
                    if now - last_ping > 20:
                        self._ctl({"cmd": "ping"})
                        last_ping = now
                    if now - last_rx > 70:
                        raise ConnectionError(tr("Server ไม่ตอบสนอง"))
                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        raise ConnectionError(tr("Server ปิดการเชื่อมต่อ"))
                    last_rx = time.time()
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        try:
                            msg = json.loads(line.decode("utf-8"))
                        except ValueError:
                            continue
                        cmd = msg.get("cmd")
                        tok, frm = str(msg.get("token", "")), msg.get("from", "?")
                        if cmd == "connect":
                            if msg.get("direct") and self.server.relay.get("direct", True):
                                threading.Thread(target=self._direct, args=(tok, frm, msg), daemon=True).start()
                            else:
                                threading.Thread(target=self._data, args=(tok, frm), daemon=True).start()
                        elif cmd == "open":                 # ต่อตรงไม่สำเร็จ → ใช้ Relay
                            ls = self.direct.pop(tok, None)
                            if ls:
                                try:
                                    ls.close()
                                except Exception:
                                    pass
                            threading.Thread(target=self._data, args=(tok, frm), daemon=True).start()
                        elif cmd == "kick":
                            self.server.log(tr("ผู้ดูแล Server สั่งตัดการเชื่อมต่อ"))
                            self.server.kick()
            except Exception as e:
                if not self.stop_event.is_set() and str(e):
                    self.status("error", err_text(e))
            finally:
                try:
                    self.sock.close()
                except Exception:
                    pass
            if self.stop_event.wait(wait):
                break
            backoff = min(backoff * 2, 60)
        self.status("off", tr("ปิดการเชื่อมต่อ Server แล้ว"))

    def _direct(self, token, from_ip, msg=None):
        """เชื่อมต่อตรงกับเครื่องที่ควบคุม (P2P): เปิดพอร์ตชั่วคราว + ลองต่อออกไปหาอีกฝั่งพร้อมกัน
        รับเฉพาะผู้ที่มี token จาก Server — ถ้าไม่สำเร็จ Server จะสั่ง "open" ให้ใช้ช่องผ่าน Server แทน"""
        msg = msg or {}
        ls, port = p2p_listen(self.server.relay.get("direct_port", 0))
        if ls is None:
            return self._data(token, from_ip)
        self.direct[token] = ls
        peer_new = int(msg.get("p2p") or 0) >= P2P_PROTO
        try:
            cands = p2p_cands(ls, port)
            self._ctl({"cmd": "cands", "token": token, "lan": cands, "port": port, "p2p": P2P_PROTO,
                       "fixed": bool(self.server.relay.get("direct_port") and port == self.server.relay.get("direct_port"))})
        except Exception:
            self.direct.pop(token, None)
            ls.close()
            return
        peer = [str(c) for c in (msg.get("ccands") or [])][:10] if peer_new else []
        try:
            sock, how = p2p_race(token, peer, ls, False, timeout=9.0, legacy=not peer_new)
        finally:
            self.direct.pop(token, None)
            try:
                ls.close()
            except Exception:
                pass
        if sock is not None:
            try:
                ip = sock.getpeername()[0].replace("::ffff:", "")
            except OSError:
                ip = from_ip
            self.server._client(sock, (ip, 0))

    def _data(self, token, from_ip):
        try:
            ds = _relay_socket(self.addr)
            line_send(ds, {"role": "data", "token": token, "v": 1})
        except Exception as e:
            self.server.log(tr("เชื่อมต่อไม่สำเร็จ: %s") % err_text(e))
            return
        self.server._client(ds, (from_ip, 0))


# ============================================================================
# ฝั่งเครื่องที่ควบคุม (Client)
# ============================================================================
def client_connect(host, port, password, confirm_fp, relay=None):
    """เชื่อมต่อ + ยืนยันตัวตน คืนค่า (tls_socket, info, fingerprint)
    confirm_fp(host, fp) -> bool  ใช้ตรวจ Certificate ของปลายทาง"""
    if not relay or not relay.get("addr"):
        raise ConnectionError(tr("ยังไม่ได้ตั้งค่า Server — ไปที่แท็บ \"ตั้งค่า Server\""))
    raw, route, presence = relay_dial(relay["addr"], relay.get("key", ""), relay["id"], relay.get("direct", True))
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def drop_presence():
        if presence is not None:
            try:
                presence.close()
            except Exception:
                pass
    try:
        tls = client_context().wrap_socket(raw)
    except Exception:
        raw.close()
        drop_presence()
        raise ConnectionError(tr("เชื่อมต่อกับเครื่องปลายทางไม่สำเร็จ — ลองใหม่อีกครั้ง"))
    try:
        fp = fingerprint(tls.getpeercert(binary_form=True))
        t, p = recv_msg(tls)
        hello = jload(p) if t == T_HELLO else {}
        if hello.get("app") != APP:
            raise ConnectionError(tr("เครื่องปลายทางไม่ได้ใช้โปรแกรม NetRemote"))
        if not confirm_fp(host, fp, hello.get("name", "")):
            raise ConnectionError(tr("ยกเลิกการเชื่อมต่อ — ยืนยันตัวตนของเครื่องปลายทางไม่ได้"))
        nonce = base64.b64decode(hello["nonce"])
        send_msg(tls, T_AUTH, jdump({"mac": auth_mac(password, nonce, fp), "name": computer_name(), "chat": 1,
                                     "os": SYSTEM}))
        tls.settimeout(70)                          # ปลายทางอาจต้องกดยืนยัน
        t, p = recv_msg(tls)
        if t == T_ERR:
            raise ConnectionError(tr(jload(p).get("msg", "ถูกปฏิเสธ")))
        if t != T_OK:
            raise ConnectionError(tr("การเชื่อมต่อขัดข้อง"))
        info = jload(p)
        info["route"] = route
        tls.settimeout(None)
        if presence is not None:
            def hold():                             # ปิดช่องกับ Relay เมื่อจบเซสชัน (ใช้แสดงในหน้ามอนิเตอร์)
                while tls.fileno() != -1:
                    time.sleep(2)
                drop_presence()
            threading.Thread(target=hold, daemon=True).start()
        return tls, info, fp
    except Exception:
        try:
            tls.close()
        except Exception:
            pass
        drop_presence()
        raise


def discover_lan(port, timeout=0.5):
    local = get_local_ip()
    net = ipaddress.ip_network(local + "/24", strict=False)

    def probe(ip):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return ip if s.connect_ex((ip, port)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    with ThreadPoolExecutor(max_workers=64) as ex:
        found = [ip for ip in ex.map(probe, [str(h) for h in net.hosts()]) if ip]

    def name(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""
    with ThreadPoolExecutor(max_workers=16) as ex:
        names = list(ex.map(name, found))
    return [(ip, n, ip == local) for ip, n in zip(found, names)]


KEYMAP = {
    "Return": "enter", "KP_Enter": "enter", "BackSpace": "backspace", "Tab": "tab", "ISO_Left_Tab": "tab",
    "Escape": "esc", "Delete": "delete", "KP_Delete": "delete", "Up": "up", "Down": "down",
    "Left": "left", "Right": "right", "Home": "home", "End": "end", "Prior": "page_up",
    "Next": "page_down", "Insert": "insert", "space": "space", "Shift_L": "shift", "Shift_R": "shift_r",
    "Control_L": "ctrl", "Control_R": "ctrl_r", "Alt_L": "alt", "Alt_R": "alt_r", "Option_L": "alt",
    "Option_R": "alt_r", "Meta_L": "cmd", "Meta_R": "cmd_r", "Super_L": "cmd", "Super_R": "cmd_r",
    "Win_L": "cmd", "Win_R": "cmd_r", "Command": "cmd", "Caps_Lock": "caps_lock", "Print": "print_screen",
    "Menu": "menu", "App": "menu", "Num_Lock": "num_lock", "Pause": "pause", "Scroll_Lock": "scroll_lock",
}
KEYMAP.update({"F%d" % i: "f%d" % i for i in range(1, 21)})
SWAP = {"cmd": "ctrl", "cmd_r": "ctrl_r", "ctrl": "cmd", "ctrl_r": "cmd_r"}


def mods_from_state(st):
    m = []
    if st & 0x4:
        m.append("ctrl")
    if SYSTEM == "Darwin":
        if st & 0x8:
            m.append("cmd")
        if st & 0x10:
            m.append("alt")
    elif SYSTEM == "Windows":
        if st & 0x20000:
            m.append("alt")
    else:
        if st & 0x8:
            m.append("alt")
        if st & 0x40:
            m.append("cmd")
    return m


# ============================================================================
# GUI
# ============================================================================
def run_gui():
    import tkinter as tk
    from tkinter import messagebox, simpledialog, ttk
    from PIL import Image, ImageTk
    import tkinter.font as tkfont

    # ------------------------------------------------------------------
    # ธีม (สว่าง / มืด) — สีม่วงเข้ากับไอคอนโปรแกรม
    # ------------------------------------------------------------------
    PALETTES = {
        "light": dict(bg="#F3F4F8", card="#FFFFFF", border="#E3E6EE", text="#1D2130", muted="#6B7280",
                      subtle="#EEF0F6", hover="#E3E6F0", field="#FFFFFF", accent="#6D4AFF", accent_hover="#5A37F0",
                      accent_fg="#FFFFFF", sel="#ECE7FF", ok="#15803D", ok_bg="#E6F6EC", warn="#B45309",
                      warn_bg="#FFF3E0", danger="#DC2626", danger_bg="#FDECEC", danger_hover="#B91C1C",
                      header="#5B3AE6", header2="#7353FF", hdr_fg="#FFFFFF", hdr_muted="#DCD3FF", viewer="#0F1115"),
        "dark": dict(bg="#121419", card="#1B1E26", border="#2B303B", text="#E8EAF0", muted="#9AA3B2",
                     subtle="#252A34", hover="#2F3542", field="#21252E", accent="#8B6CFF", accent_hover="#A08AFF",
                     accent_fg="#FFFFFF", sel="#352C5E", ok="#4ADE80", ok_bg="#14301F", warn="#FBBF24",
                     warn_bg="#3A2B10", danger="#F87171", danger_bg="#3A1818", danger_hover="#EF4444",
                     header="#2E2370", header2="#3D2F94", hdr_fg="#FFFFFF", hdr_muted="#B9AEF0", viewer="#0A0B0E"),
    }

    def detect_dark():
        try:
            if SYSTEM == "Darwin":
                r = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"], capture_output=True, timeout=2)
                return b"Dark" in r.stdout
            if SYSTEM == "Windows":
                import winreg
                k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
                return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
        except Exception:
            pass
        return False

    class Theme:
        def __init__(self, root, mode="auto"):
            self.root, self.mode = root, mode if mode in ("auto", "light", "dark") else "auto"
            self.items, self.callbacks = [], []
            fam = tkfont.nametofont("TkDefaultFont").actual("family")
            sz = 13 if SYSTEM == "Darwin" else 10
            mono = "Menlo" if SYSTEM == "Darwin" else ("Consolas" if SYSTEM == "Windows" else "DejaVu Sans Mono")
            F = tkfont.Font
            self.f = {"base": F(family=fam, size=sz), "small": F(family=fam, size=sz - 2),
                      "smallbold": F(family=fam, size=sz - 2, weight="bold"), "bold": F(family=fam, size=sz, weight="bold"),
                      "h1": F(family=fam, size=sz + 7, weight="bold"), "h2": F(family=fam, size=sz + 3, weight="bold"),
                      "big": F(family=fam, size=sz + 3), "mono": F(family=mono, size=sz + 5, weight="bold"),
                      "monobig": F(family=mono, size=sz + 12, weight="bold"),
                      "status": F(family=fam, size=sz + 5, weight="bold")}
            for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont"):
                try:
                    tkfont.nametofont(name).configure(family=fam, size=sz)
                except Exception:
                    pass
            self.apply()

        def c(self, k):
            return self.p[k]

        def track(self, w, **roles):
            self.items.append((w, roles))
            self._paint(w, roles)
            return w

        def _paint(self, w, roles):
            try:
                w.configure(**{opt: self.p[key] for opt, key in roles.items()})
            except tk.TclError:
                pass

        def on_change(self, fn):
            self.callbacks.append(fn)

        def set_mode(self, mode):
            self.mode = mode
            self.apply()
            for fn in list(self.callbacks):
                try:
                    fn()
                except Exception:
                    pass

        def apply(self):
            self.is_dark = self.mode == "dark" or (self.mode == "auto" and detect_dark())
            p = self.p = PALETTES["dark" if self.is_dark else "light"]
            s = ttk.Style(self.root)
            s.theme_use("clam")
            f = self.f
            s.configure(".", background=p["bg"], foreground=p["text"], fieldbackground=p["field"],
                        bordercolor=p["border"], lightcolor=p["border"], darkcolor=p["border"],
                        troughcolor=p["subtle"], focuscolor=p["accent"], selectbackground=p["accent"],
                        selectforeground=p["accent_fg"], insertcolor=p["text"], arrowcolor=p["muted"], font=f["base"])
            s.configure("TFrame", background=p["bg"])
            s.configure("Card.TFrame", background=p["card"])
            s.configure("TLabel", background=p["bg"], foreground=p["text"])
            s.configure("Muted.TLabel", background=p["bg"], foreground=p["muted"], font=f["small"])
            s.configure("Link.TLabel", background=p["bg"], foreground=p["accent"])
            s.configure("H2.TLabel", background=p["bg"], foreground=p["text"], font=f["h2"])
            # ปุ่ม
            for name, bg, fg, hov, font in (("TButton", p["subtle"], p["text"], p["hover"], f["base"]),
                                            ("Accent.TButton", p["accent"], p["accent_fg"], p["accent_hover"], f["bold"]),
                                            ("Danger.TButton", p["danger"], "#FFFFFF", p["danger_hover"], f["bold"])):
                s.configure(name, background=bg, foreground=fg, bordercolor=bg, lightcolor=bg, darkcolor=bg,
                            relief="flat", padding=(14, 7), focusthickness=0, font=font, anchor="center")
                s.map(name, background=[("disabled", p["subtle"]), ("pressed", hov), ("active", hov)],
                      foreground=[("disabled", p["muted"])],
                      bordercolor=[("active", hov), ("disabled", p["subtle"])],
                      lightcolor=[("active", hov), ("disabled", p["subtle"])],
                      darkcolor=[("active", hov), ("disabled", p["subtle"])])
            for base in ("Accent.TButton", "TButton", "Danger.TButton"):
                s.configure("Tool." + base, padding=(9, 5), font=f["small"] if base == "TButton" else f["smallbold"])
                s.map("Tool." + base, **{k: s.map(base, k) for k in ("background", "foreground", "bordercolor",
                                                                     "lightcolor", "darkcolor")})
                s.configure("Big." + base, padding=(18, 11), font=f["h2"] if base != "TButton" else f["bold"])
                s.map("Big." + base, **{k: s.map(base, k) for k in ("background", "foreground", "bordercolor",
                                                                    "lightcolor", "darkcolor")})
            # ช่องกรอก
            for name in ("TEntry", "TCombobox", "TSpinbox"):
                s.configure(name, fieldbackground=p["field"], foreground=p["text"], bordercolor=p["border"],
                            lightcolor=p["field"], darkcolor=p["field"], background=p["field"], padding=(8, 6),
                            arrowcolor=p["muted"], insertcolor=p["text"], selectbackground=p["sel"],
                            selectforeground=p["text"])
                s.map(name, bordercolor=[("focus", p["accent"])], lightcolor=[("focus", p["field"])],
                      fieldbackground=[("readonly", p["field"]), ("disabled", p["subtle"])],
                      foreground=[("disabled", p["muted"])], background=[("active", p["field"])],
                      selectbackground=[("readonly", p["field"])], selectforeground=[("readonly", p["text"])])
            self.root.option_add("*TCombobox*Listbox.background", p["field"])
            self.root.option_add("*TCombobox*Listbox.foreground", p["text"])
            self.root.option_add("*TCombobox*Listbox.selectBackground", p["sel"])
            self.root.option_add("*TCombobox*Listbox.selectForeground", p["text"])
            self.root.option_add("*TCombobox*Listbox.font", f["base"])
            # Checkbox
            for name, bg in (("TCheckbutton", p["bg"]), ("Card.TCheckbutton", p["card"])):
                s.configure(name, background=bg, foreground=p["text"], indicatorbackground=p["field"],
                            indicatorforeground=p["accent_fg"], upperbordercolor=p["border"],
                            lowerbordercolor=p["border"], indicatormargin=(0, 0, 8, 0), padding=(0, 4), focusthickness=0)
                s.map(name, background=[("active", bg)],
                      indicatorbackground=[("selected", p["accent"]), ("active", p["subtle"])],
                      upperbordercolor=[("selected", p["accent"])], lowerbordercolor=[("selected", p["accent"])],
                      foreground=[("disabled", p["muted"])])
            # แท็บ
            s.configure("TNotebook", background=p["bg"], bordercolor=p["bg"], lightcolor=p["bg"],
                        darkcolor=p["bg"], tabmargins=(14, 10, 14, 0))
            s.configure("TNotebook.Tab", background=p["bg"], foreground=p["muted"], bordercolor=p["bg"],
                        lightcolor=p["bg"], darkcolor=p["bg"], padding=(18, 9), font=f["bold"])
            s.map("TNotebook.Tab", background=[("selected", p["sel"]), ("active", p["subtle"])],
                  foreground=[("selected", p["accent"])], bordercolor=[("selected", p["sel"])],
                  lightcolor=[("selected", p["sel"])], expand=[("selected", (0, 0, 0, 0))])
            # ตาราง
            s.configure("Treeview", background=p["card"], fieldbackground=p["card"], foreground=p["text"],
                        bordercolor=p["card"], lightcolor=p["card"], darkcolor=p["card"],
                        rowheight=int(f["base"].metrics("linespace") * 1.9), font=f["base"])
            s.map("Treeview", background=[("selected", p["sel"])], foreground=[("selected", p["text"])])
            s.configure("Treeview.Heading", background=p["subtle"], foreground=p["muted"], relief="flat",
                        bordercolor=p["subtle"], lightcolor=p["subtle"], darkcolor=p["subtle"],
                        font=f["smallbold"], padding=(8, 6))
            s.map("Treeview.Heading", background=[("active", p["hover"])])
            s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
            for orient in ("Vertical", "Horizontal"):
                s.configure(orient + ".TScrollbar", background=p["subtle"], troughcolor=p["card"],
                            bordercolor=p["card"], lightcolor=p["subtle"], darkcolor=p["subtle"],
                            arrowcolor=p["muted"], gripcount=0, arrowsize=12)
                s.map(orient + ".TScrollbar", background=[("active", p["hover"])])
            s.configure("TSeparator", background=p["border"])
            s.configure("Horizontal.TProgressbar", background=p["accent"], troughcolor=p["subtle"],
                        bordercolor=p["subtle"], lightcolor=p["accent"], darkcolor=p["accent"])
            self.root.configure(bg=p["bg"])
            for w, roles in list(self.items):
                try:
                    if w.winfo_exists():
                        self._paint(w, roles)
                    else:
                        self.items.remove((w, roles))
                except tk.TclError:
                    self.items.remove((w, roles))

    T = None   # กำหนดค่าเมื่อสร้างหน้าต่างหลัก

    def card(parent):
        return T.track(tk.Frame(parent, highlightthickness=1, bd=0),
                       bg="card", highlightbackground="border", highlightcolor="border")

    def lbl(parent, text="", fg="text", bg="card", font="base", **kw):
        kw.setdefault("anchor", "w")
        kw.setdefault("justify", "left")
        return T.track(tk.Label(parent, text=text, font=T.f[font], **kw), fg=fg, bg=bg)

    def box(parent, bg="card"):
        return T.track(tk.Frame(parent, bd=0, highlightthickness=0), bg=bg)

    APP_ICON = ("iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAALaUlEQVR42u1be3BcVRn/fefc3b13d7ObNEnTliLEPih9Ai0CAtZSniLgg6B1BsWO8nCccRjEoSJWXsoM4wyIo6OWDoiO0IzyFhQUSgvCYFsoJFJTQ1P6SNo0yW52s3v33ns+/7i7ee7zJk3q2JO5k8lm997vfOf3/b7f952zwPFxfBwf/8+DvH2MqakJYuEh0KLp4JZm8FQY39oEWngI1Dod3NwMBdDRtoNpUxPLY3U1XduYjgoC1oPFnSAFACsXrg+fVnXd+Rrp5wpgAYNrmZm4wod7h6270kKIHjDtsmC+sf/Qi681t98QA4Cmpk2yufkaZ8IcsHLlK9rmzavspQ23hC5qvPlbUujXayIwV5IfDAVmNTXxSwIEAcUWLJXeYzvpjds6mx/a3HFz3/qVr2h3bl5lj9sBucmvPX3rilp9/gZdq16WUUnYTloBUACIpgjyPPiLhSZ04ZdhpJ34B73p3ddv2H72lnKcQGVNfvmbl9cG5j2uCX/YtOM2SAgCxLEU/wxmMDt+GdYUO2ZPuv2rG7av2JSbQ8UOaMIm2YxrnDXLnv3E7NA5fwdRyHbSDpE4ZkkQAJiVI4VfEoTVldxxyW/fvfCVYpwgCrE9ACz52Fdq6vUljwrhD1lOygEJyTi2f0AkbZVxiIRvmj7/kQsa1zWgGShE0HlX8/rls3yPHfyafcXcDbfW6HObUnavLUhojP+NQUTCVhk7FKiv0bUGeuzghX85uHyWb9vB51Q5DqBtBw00Tp8zfWHd1b8ioioFm3gKyc4TORJIsQ0ibYHlxJ94vu3uPvc/dxYPgaYmFkCzs6J+7acDsnp2xkkxQCJ349EXKHuXqbiogE1ZHNjKVLpv2rRT6q+5GIBav/LVMQuujX6hpn2bAOCEA7POk8LHcKAYLMbCDGAGMiYDUxgbvgAN2pIHCQwSHArUnwfg4dbDh0VJB2xNPUsAdCn0+YoV8aCfacTkMxZDCGBGo5bFx+TjnAF077NhZQCfn0Y5wcWnYps0MuYCCLW0NpslHZBpfYsAGERatYLjZljQILiIANtmhKIC37yvDnOW+SG1qWEH5TA6Wi38+rZuxA470HwjncBgUnDAENUAgq1oKekAspAiAFKBicFQUETDqIIEMJBUuPKmKOYvDwAAOvfGYVsOaJJokpkhpcDMk6NoXOLHZWsjeGT9EYRrBNgZ4YDsjyKX8JNZ5hgKWi2/uoQAM40klREMi0i9ACvg6Y078Yt1r8II+aDU5JCBEISBRAZrbz8XX/7OCkTqBEi6PMCjbB02h7yBqhWEF9SQuBh2W8561rEZJIBd2zphpm0Ew/78TDRcb06UfwiwLYV/besECTcUhkmhMQgo9mCtWC4thAAeVgH5DQ1SUmFhnQWcEG58MvOEocBvaIPPyGdv7u9itaooUlwM897YK/cgVoyic2KAiDCQsODYCkLQBPGA++whxBazlSt3AArernIkK6XwxZtORyjiRyppQWpHJ296sVUULTCLFR1lukEIQjpp45I1p+LHmz6HaK2BZMycUCdwSWuVlxAofZUdr5LQeziFuUvq8cALTfj4ojrEjqSg+cRRX/1StorCWQAlEFDZ0HwCSjFOaKzGT5+9Gmdf3IieQwMThIRia8/eQqA4+Nkzc9sZhXA0gHsfvwpXrl2K3sMDEILGLaJK9gkmmgS9JjMhCaxcDXHLgxfiG3eci/6+NJjZc4YoZafHNKgmhATz6hhBAAjKYVz7vbPw3YcugpmyYabs7P+OAQQcjdXP6QalGEQuGgDgM9cuxgMvNKFuVhiOpTx1XrzaW0QKF76F8sgCrBhyGPPvb+/Dhrteh5QEI+xHdZ2BI50JSGgVurmUbvUghQfVFo99zcvsbUuBBKG9pRtHupI484KTMH12FQ7uiWHnG/uhB33wBSQCuqxYLufsHG2vqxY9C6GJS4OOoxCt1dHZEcetn/8Tfvn9zbAyDnx+ievWnYNglbv6AV2D11JhkjmgfBcoxdANH3Zs+QjrvvQUEn1pdPy7B6890wYAOGPliVhwRgMSMXNcXdcJF0I8QVIYAKRP4OG73kBnRxzBKj+kJtD88+1QiuHXNVyxdimsjPeGSikprLyQYClaGTFBKdz8nqcezrVfAoYGIhcR4UgA7S3deO6R96AcxjMPv4uqGh0YlhlKaQkpxYjyu1g57CkLoERDJBerrBix3hRIEBxblb9mRLj/2y8hY9rw+WU2/hnlbFhLjRDrSUPZPNgiK94QUd7SYH64ExQzpOY2OD67dhkGElb5Jw0YEMIVQ0Rur4CZoRxGuR01AuA4jC/ceDqUch2ieKxML4cEtdJxNbYhKSRh29YEPnV5FKecVo87Nl42pTtB/9ySGNEZmqAQyN9TsxXDCAtseTEG6QNWnB8GCUCUQ2AE2BZj3mIDdQ2+wXxPROjttrFr54DbYi8DCcwMZsK7bybx0pO9MKoIjqPyhgB7FUIFw4MZfoPw8lN9ePnJ3rJ3DYUkxHst3P7gSVh9VTUcJ7uzJglt76fwwxv2IhyR5XeXs28LVomi+oG9ZYHiKY8ZCEVERd1eIQlKSWi+fKmSEIoKhMKifAfQ0AZJuQgedxocqfBKNBuGb0PQkFElnU489BkGlMcjSOWolaJZQI2j9CUCkkkF5QxNXkpCf8yGZXHeWqE/5oAZIxAgBGAEhSeJnJNByjsJeit9SQCplMJZqyJYfWUNKPsaEcG2FOYtCg52iHJjwbIQ7v1NY3Z/j90ihoAtL8aw5a990A1RMRLGlQW4gBAq98maD7jxtlmoa/AVrOBy0cEM1NRp+OTqyJj3LVkewttb47Btdze6EiR4Koac2dMJgO2w1Q8QGMTldIhHH5qwLEbrO8mCJEluUygrhgpPovWdJEzTcbfAuDI7XD4RUMpKALBmYyaViwArY/XvgSHYS+tDMSB9wM/u3oen/9CNbAesYhQxgL3/SWcFTuWWMMBEki2V6ACQxuwTgX1vclEH6PoMBYD7kq07qqsWfT13Yqyi/gy7Kc+2FVrfSYxL5fl1AZGVuhXxkBvGpNiheKp9OwBHyiCXRMDu3TsdoEZvO7DxrRm1q7r9MlLrcIapwmpdsdv300Pj6/szZ+9VKQrBLISP0lZP/+7O370OQHZ07EmX0Q/Y7EybNo/jqba9fckPnpQyRIrdxFTReb1cElLju5grfXK2/mOlNFlF8VTb8919/9hdU7McwOayjskhlTIQgqZ39b+9b2bt6kv9WjTqKFNN2hGQ8e4TsVJSGtLMHOnZ0X7HOjL7DvWnKQnE7LIcAPQgGK2T/cl2E5AHaiMrLiUhhWKbj3UnMCslSCMQUXvnYz/Y2/XH14PRmQOmuTeVrzFQ8NyvacZUMFgX6OrZcsDvr+2tDi0+X8qAtJXpEJVKXlM09ezKgwQ+6nr6/vc+vGeTYZyYSiQ+igHIe1a42MFntqwBW9dnBg4c/vNuxfaH0fCpS3V/fYTZJsW2YkBlo46n8FIMBRKa8GvVImP1dbfvf/Se9/fc26zrMwbS6QM9ADKFElmpVZQAdF2fWZtOHwwbxsnzTpvzozWR4KkXB3w1NSABZsdtO07BYUkiASIJsIJpx+L9iV1/a+n4ye9jiZYPAoGGpGl2dQNIFVr9chyQc0LAMGqrU6kjEQDBsDF3zsmz1pwZMRYs9vurTxDkr8IkfV1mCJ/Eiq2kZcf2x5NtLR1dT7wdT7a0ARgwjGnxVKqnD0C62OTLdUAuXfqAaDAQ0KOm2WW4f0MHEAQQgOdvoI1rK8DMrnAKgBUINKRNMxUD4kkAFopvDFfkgNx7pSueonowGDUcxwwAKc0007nKnyZx8hwI6AowbCkD5sBALAXEzOzEnXLFqxeDR58Pl5M8+dHVrspOOPcdJq50MuPioWMlB+L4OD48jf8CteW23mcLq8wAAAAASUVORK5CYII=", "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAF7ElEQVR42qWXT2xcVxXGf+fe9+aPZ/wnEyc0qkIDTaI0aqmSACo0osVRlAASElFn0VDRSsCmoAqhsEhRsb1B0EVRWCCoWABNpcqhlUClUlthIaEqWTRAola4VIS0SVPHsTWJ7bFn5r13Dovx2DPj6cSN79Nd3X/f++53vnuOcPMmYNxaE7jFxTJWND88bI51tuFhc2NF8w00HSG2NhNw1gRcihTdKQCmZG3HbrYicIpT2sqACYh1AbAy4Yf3vf/NQHqKRrLdTMM6lyZrI76+h4iLBLkQWfWPvziz9SSg7SCWNzRMHM4e2fXaxs0Ddz+fDQuH1GLUonVdgZMQJwGVqDQ+uXDu4ZPnD08ZKg2QQWPiyDCyd/S7wUD/nWPZ1KahcnQ1wnCIyLoQmBmC5lKbhzbozhcfuONbB0feo9YYdQBjRfOjo6Kf2fOdR/KpLUNz0WRkEOLFi8etp+PFG4Rz0VQtn9myf8fgE4+NIjpWrJ8dALy9GwMkE/YdjSxSNXPOQXVRqS4oto4oTGcd6axgaj7Sqoau9yjwbHEMReoAZHRUFDb2Gv5TsVUdDq1Wle1709z/9X7ClK+Lea23YQYIcaScfvkG77xZIUyLxFZ15ty2/v5P9otICUyClVXVtKKBYShKrPDw8QKX/3eBc2euks0HmNapEBGsCy3ihEo5Zte+TRx9cgdPHfmABBAMQ30qyqcbc4PmhYqKYqgZ4usB/NzTZzn92vvk8ylUDVMjSYxU2qOJdXQS54T5+Rr7vnQ7I7/bjoSgmoh6I2kL5TYA1tTrUdu7Ic3GTT3k+lIksZLKBPQVMlx6t0TvQJoksY4A0j0BfYU0BvUfkpW9W+a2AmgFYQKaGHGsJImSxEpUS/jxb7/Cg9/YybUr8wDLY+1dE4OWnzKsGwBrm9xulSJCHCX05FI8+exhHvreXmYmy1hiXfXZCkC7AWhgbCBdTa94oVZN0MR44ukvc/zXh/CBawi/c1A0fV2vIFlFV4fNFILQ4bwwd71K4bYcnzuwjVol7miatkpb3TRg2tLbEZgZYegoz1Z54cSbZHMhf/jZGcZfnCCbSy2HaTuEVft200AzC2b1e/fe4ZzgvCNIeU4cG+fEsXH++9Y1fvDMAZwTxAuuqXvvcCKYdYiujwpDaxKiAT4UKosxpekF4ihd94EZ48OLswShZ/TRv9A/mKVaSYinFpYZc16Yv1GlshAThNKigfaL7egDCNRi5fpMxLETQxQfL5HK+DojS04Xx8b89Yg4Vh47/nmCQJbHEahVErZuH2C2lFCtJaSz0lEDHQEkKD6EX/7kMnu+2Ecqs2HpOsAHQnVR2XVvD0MP5QB44/UF/nWmTKbHkcS2/Hid+2fCudOXcAEoSoOL8k0BmOFCYXqqxp+fv7p8eBQZUc2YLcUcLha4/+A2AF5/aYo/nZymvxAQhkKYkuU12ZwnCIWkyQ27MKAtAnQh9Bb8kgEZg58IufuzOSoLyu49OXxQ1/AXDvaRH/Bkehxv/6PM1IcRYVh/sFQhsRUPSD4agJhi2uwAZqAJOA9z8zEPfK2f7z91+4pvLL0Dh44UOHSkAMBvfn6Fl567Rt9AsGTFbWZkqiLT1gzAzExEZC62ymUkuEPNrNlTNDGyecffXi1x/uz8ki3XHx2gHh1LW5ZmYrJ5IU60PUVQE+dirVwpl6dml86sMzAyggC10vzEK7nMtv0qpgK+PbuJYuODS5WuuUgQSj1faKPaxFRcyt9YePcVYHFkBAdoS1aczRS27r/rhZf783fdU61NxwZOpNXhb5YU2Sr3xATTdGowuLHwn4m/v/Xtr1ar711spObSWhM86DdtiO+799Ojv8pn77xHrYZZvK6kWCTASYry4oV/n7/408evzvz1DbC4A4DlwiQN7Ni385lH+/K7D3iX3VLXin38jBRLEq1MzpYnxs++86PfQzQBwzUY1ZuUZhIAGeC2IMgMQiaAj8tEAFTiOK7MAJPAYvOfr6moLBbHPHUxBrfYfbE41rXIlbXTeculUdfR/wPSy1zVyYUKYQAAAABJRU5ErkJggg==")

    def set_app_icon(win):
        """ใช้ไอคอนของโปรแกรมแทนโลโก้ Tk ที่มุมหน้าต่าง"""
        try:
            imgs = [tk.PhotoImage(master=win, data=d) for d in APP_ICON]
            win.iconphoto(True, *imgs)
            win._app_icons = imgs
        except Exception:
            pass


    # ------------------------------------------------------------------
    class Viewer:
        def __init__(self, app, tls, info, host, fp):
            self.app, self.info, self.host, self.fp = app, info, host, fp
            self.lock = threading.Lock()
            self.frame = None
            self.cursor = None
            self.dirty = False
            self.photo = None
            self.geom = (0, 0, 1, 1)
            self.closed = False
            self.stats = {"frames": 0, "t0": time.time(), "b0": 0}
            self.pressed = set()
            self.last_click = (0, None, 0, 0, 1)
            self.pending_move = None
            self.inside = False
            self.can_control = bool(info.get("control"))

            win = self.win = tk.Toplevel(app.root)
            win.title("%s — %s (%s)" % (info.get("name", host), APP, host))
            win.geometry("1280x800")
            win.minsize(480, 320)
            win.protocol("WM_DELETE_WINDOW", self.disconnect)

            T.track(win, bg="bg")
            mons = info.get("monitors") or [{"w": 0, "h": 0}]
            self.mvals = [tr("จอ %d (%d×%d)") % (i + 1, m["w"], m["h"]) for i, m in enumerate(mons)]
            self.mon_var = tk.StringVar(value=self.mvals[0])
            self.q_var = tk.StringVar(value=app.cfg.get("quality", tr("ปกติ")))
            self.ctrl_var = tk.BooleanVar(value=self.can_control and not app.view_only_var.get())
            remote_mac = info.get("os") == "Darwin"
            self.swap_var = tk.BooleanVar(value=(SYSTEM == "Darwin") != remote_mac)
            self.rtt = self.rtt_avg = self.rtt_min = self.rtt_max = None
            self.last_pong = time.time()
            self.peer_name = info.get("name", host)

            self.body = box(win, bg="viewer")
            self.body.pack(fill="both", expand=True)
            self.canvas = T.track(tk.Canvas(self.body, highlightthickness=0, cursor="arrow"), bg="viewer")
            self.canvas.pack(side="left", fill="both", expand=True)
            self.img_item = self.canvas.create_image(0, 0, anchor="nw")
            self.cur_item = self.canvas.create_polygon(0, 0, 0, 0, fill="white", outline="black", width=1)
            self.wait_item = self.canvas.create_text(300, 200, text=tr("กำลังรับภาพหน้าจอ…"), fill="#9AA3B2",
                                                     font=T.f["h2"])


            c = self.canvas
            c.bind("<Configure>", lambda e: self._mark_dirty())
            c.bind("<Enter>", self._enter)
            c.bind("<Leave>", self._leave)
            c.bind("<Motion>", self._motion)
            for n in (1, 2, 3):
                c.bind("<ButtonPress-%d>" % n, lambda e, n=n: self._button(e, n, True))
                c.bind("<ButtonRelease-%d>" % n, lambda e, n=n: self._button(e, n, False))
            c.bind("<MouseWheel>", lambda e: self._wheel(e, False))
            c.bind("<Shift-MouseWheel>", lambda e: self._wheel(e, True))
            c.bind("<Button-4>", lambda e: self._send_scroll(0, 1))
            c.bind("<Button-5>", lambda e: self._send_scroll(0, -1))
            c.bind("<KeyPress>", lambda e: self._key(e, True))
            c.bind("<KeyRelease>", lambda e: self._key(e, False))
            c.bind("<FocusOut>", lambda e: self._release_all())

            self.chan = Channel(tls, self._on_message, self._on_close, idle_timeout=15)
            self.files = FileClient(self.chan)
            self.fw = None
            # แชท + โทร: แผงด้านขวา กว้าง 1/8 ของหน้าจอ ซ่อน/แสดงได้
            self.cq = queue.Queue()
            self.chat = ChatEngine(self.chan, self.cq.put, info.get("name", host))
            self.call = CallEngine(self.chan, self.cq.put)
            pw = max(344, int(win.winfo_screenwidth() / 8))
            self.panel = ChatPanel(self.body, self.chat, self.call, self.peer_name, mode="controller", width=pw,
                                   on_hide=lambda: self.toggle_chat(False), viewer=self,
                                   chat_ok=bool(info.get("chat")), subtitle=tr("เชื่อมต่อแล้ว"))
            self.panel.on_unread = self._on_unread
            self.panel_shown = False
            self._build_dock()
            self.toggle_chat(bool(app.cfg.get("panel_open", True)))
            self.chan.start()
            self.win.after(40, self._chat_poll)
            self.request(full=True)
            self.win.after(16, self._render_loop)
            self.win.after(1000, self._stats_loop)
            self.win.after(15, self._flush_move)
            self.win.after(200, self._ping_loop)

        # ----- network side (I/O thread) -----
        def params(self):
            q = next((x for x in QUALITY if x[0] == self.q_var.get()), QUALITY[1])
            try:
                mon = self.mvals.index(self.mon_var.get())
            except ValueError:
                mon = 0
            return {"max_w": q[1], "q": q[2], "sub": q[3], "mon": mon}

        def request(self, full=False):
            p = self.params()
            if full:
                p["full"] = True
            self._last_params = p
            self.chan.send(T_REQ, jdump(p))

        def _quality_changed(self):
            self.app.cfg["quality"] = self.q_var.get()
            save_config(self.app.cfg)
            self.request(full=True)

        def _on_message(self, t, p):
            if t in FILE_TYPES:
                self.files.handle(t, p)
                return
            if t in CHAT_TYPES:
                self.chat.handle(t, p)
                return
            if t in CALL_TYPES:
                self.call.handle(t, p)
                return
            if t == T_PONG:
                try:
                    rtt = (time.monotonic() - float(jload(p)["t"])) * 1000
                except Exception:
                    return
                self.rtt = rtt
                self.rtt_avg = rtt if self.rtt_avg is None else self.rtt_avg * 0.7 + rtt * 0.3
                self.rtt_min = rtt if self.rtt_min is None else min(self.rtt_min, rtt)
                self.rtt_max = rtt if self.rtt_max is None else max(self.rtt_max, rtt)
                self.last_pong = time.time()
                return
            if t != T_FRAME:
                return
            jl = struct.unpack_from("!H", p)[0]
            meta = json.loads(p[2:2 + jl].decode())
            data = p[2 + jl:]
            tile = None
            if meta.get("w") and data:
                tile = Image.open(io.BytesIO(data))
                tile.load()
            with self.lock:
                size = (meta["fw"], meta["fh"])
                if self.frame is None or self.frame.size != size:
                    self.frame = Image.new("RGB", size, (30, 30, 30))
                if tile is not None:
                    self.frame.paste(tile, (meta["x"], meta["y"]))
                if "cx" in meta:
                    self.cursor = (meta["cx"], meta["cy"])
                self.dirty = True
            self.stats["frames"] += 1
            self.chan.send(T_REQ, jdump(self.params()))

        def _on_close(self, reason):
            self.app.q.put(("viewer_closed", self, reason))

        # ----- render (GUI thread) -----
        def _mark_dirty(self):
            self.dirty = True

        def _render_loop(self):
            if self.closed:
                return
            if self.dirty:
                with self.lock:
                    frame = self.frame.copy() if self.frame is not None else None
                    cur = self.cursor
                    self.dirty = False
                if frame is not None:
                    if self.wait_item:
                        self.canvas.delete(self.wait_item)
                        self.wait_item = None
                    cw, ch = max(1, self.canvas.winfo_width()), max(1, self.canvas.winfo_height())
                    fw, fh = frame.size
                    sc = min(cw / fw, ch / fh)
                    dw, dh = max(1, int(fw * sc)), max(1, int(fh * sc))
                    ox, oy = (cw - dw) // 2, (ch - dh) // 2
                    disp = frame if (dw, dh) == frame.size else frame.resize((dw, dh), resample=2)
                    if self.photo is not None and (self.photo.width(), self.photo.height()) == (dw, dh):
                        self.photo.paste(disp)
                    else:
                        self.photo = ImageTk.PhotoImage(disp)
                        self.canvas.itemconfigure(self.img_item, image=self.photo)
                    self.canvas.coords(self.img_item, ox, oy)
                    self.geom = (ox, oy, dw, dh)
                    self._draw_cursor(cur)
            self.win.after(16, self._render_loop)

        def _draw_cursor(self, cur):
            hide = cur is None or (self.inside and self.ctrl_var.get())
            if hide:
                self.canvas.coords(self.cur_item, 0, 0, 0, 0)
                return
            ox, oy, dw, dh = self.geom
            x, y = ox + cur[0] * dw, oy + cur[1] * dh
            s = 1.0
            self.canvas.coords(self.cur_item, x, y, x, y + 16 * s, x + 4 * s, y + 12 * s, x + 7 * s, y + 18 * s,
                               x + 9 * s, y + 17 * s, x + 6 * s, y + 11 * s, x + 11 * s, y + 11 * s)
            self.canvas.tag_raise(self.cur_item)

        def _ping_loop(self):
            if self.closed:
                return
            self.chan.send(T_PING, jdump({"t": time.monotonic(),
                                          "rtt": None if self.rtt_avg is None else round(self.rtt_avg, 1)}))
            stale = time.time() - self.last_pong > 3
            if self.rtt_avg is not None and stale:
                self.panel.set_latency(tr("ไม่ตอบสนอง"), "danger")
                self.dock_lat.configure(text="—", fg=T.c("danger"))
            elif self.rtt_avg is not None:
                word, _c = latency_style(self.rtt_avg)
                lv = "ok" if self.rtt_avg < 80 else ("warn" if self.rtt_avg < 150 else "danger")
                self.panel.set_latency("%.0f ms · %s" % (self.rtt_avg, word), lv)
                self.dock_lat.configure(text="%.0f ms" % self.rtt_avg, fg=T.c(lv))
            self.win.after(1000, self._ping_loop)

        def _stats_loop(self):
            if self.closed:
                return
            now = time.time()
            dt = now - self.stats["t0"]
            fps = self.stats["frames"] / dt if dt else 0
            kbs = (self.chan.bytes_in - self.stats["b0"]) / 1024 / dt if dt else 0
            self.stats.update({"frames": 0, "t0": now, "b0": self.chan.bytes_in})
            self.win.after(1000, self._stats_loop)

        # ----- input -----
        def _norm(self, e):
            ox, oy, dw, dh = self.geom
            return (max(0.0, min(1.0, (e.x - ox) / dw)), max(0.0, min(1.0, (e.y - oy) / dh)))

        def _input(self, msg):
            if self.ctrl_var.get() and self.can_control:
                self.chan.send(T_INPUT, jdump(msg))

        def _enter(self, e):
            self.inside = True
            self.canvas.focus_set()
            if self.ctrl_var.get():
                self.canvas.configure(cursor="dotbox" if SYSTEM != "Darwin" else "arrow")

        def _leave(self, e):
            self.inside = False
            self.dirty = True

        def _motion(self, e):
            self.pending_move = self._norm(e)

        def _flush_move(self):
            if self.closed:
                return
            if self.pending_move is not None:
                x, y = self.pending_move
                self.pending_move = None
                self._input({"t": "move", "x": round(x, 5), "y": round(y, 5)})
            self.win.after(15, self._flush_move)

        def _button(self, e, n, down):
            self.canvas.focus_set()
            if SYSTEM == "Darwin":
                name = {1: "left", 2: "right", 3: "middle"}[n]
            else:
                name = {1: "left", 2: "middle", 3: "right"}[n]
            x, y = self._norm(e)
            clicks = 1
            if down:
                t0, b0, x0, y0, c0 = self.last_click
                if b0 == name and time.time() - t0 < 0.45 and abs(e.x - x0) < 6 and abs(e.y - y0) < 6:
                    clicks = min(c0 + 1, 3)
                self.last_click = (time.time(), name, e.x, e.y, clicks)
            else:
                clicks = self.last_click[4] if self.last_click[1] == name else 1
            self.pending_move = None
            self._input({"t": "btn", "b": name, "d": 1 if down else 0, "n": clicks,
                         "x": round(x, 5), "y": round(y, 5)})
            return "break"

        def _wheel(self, e, horizontal):
            d = e.delta
            if SYSTEM == "Windows":
                d = int(d / 120) or (1 if d > 0 else -1)
            d = max(-10, min(10, int(d)))
            if d:
                self._send_scroll(d if horizontal else 0, 0 if horizontal else d)
            return "break"

        def _send_scroll(self, dx, dy):
            self._input({"t": "scroll", "dx": dx, "dy": dy})
            return "break"

        def _key(self, e, down):
            if not (self.ctrl_var.get() and self.can_control):
                return "break"
            ks = e.keysym
            name = KEYMAP.get(ks)
            swap = self.swap_var.get()
            if name:
                if swap:
                    name = SWAP.get(name, name)
                key = ("k", name)
                msg = {"t": "key", "k": name, "d": 1 if down else 0}
            else:
                if len(ks) == 1:
                    ch = ks
                elif e.char and len(e.char) == 1 and e.char.isprintable():
                    ch = e.char
                else:
                    return "break"
                mods = mods_from_state(e.state)
                if swap:
                    mods = [SWAP.get(m, m) for m in mods]
                key = ("c", ch)
                msg = {"t": "key", "c": ch, "d": 1 if down else 0, "m": mods}
            if down:
                self.pressed.add(key)
            elif key in self.pressed:
                self.pressed.discard(key)
            self._input(msg)
            return "break"

        def _release_all(self):
            self.pressed.clear()
            if self.can_control:
                self.chan.send(T_INPUT, jdump({"t": "release_all"}))

        def send_text(self):
            if not (self.ctrl_var.get() and self.can_control):
                messagebox.showinfo(APP, tr("เปิด \"ควบคุมเมาส์/คีย์บอร์ด\" ก่อน"), parent=self.win)
                return
            s = simpledialog.askstring(APP, tr("พิมพ์ข้อความที่จะส่งไปพิมพ์บนเครื่องปลายทาง\n"
                                            "(รองรับภาษาไทย — คลิกช่องที่ต้องการพิมพ์บนเครื่องปลายทางไว้ก่อน)"),
                                       parent=self.win)
            if s:
                self._input({"t": "type", "s": s})

        def toggle_full(self):
            full = not bool(self.win.attributes("-fullscreen"))
            self.win.attributes("-fullscreen", full)

        # ----- แชท / โทร -----
        def _build_dock(self):
            """แถบเมนูลอยด้านขวา ตอนพับแผงเก็บ"""
            d = self.dock = T.track(tk.Canvas(self.body, width=60, height=10, highlightthickness=0, bd=0), bg="viewer")
            inner = self.dock_inner = box(d)
            items = []
            av = avatar(inner, self.peer_name, 38)
            items.append((av, 4))
            self.dock_lat = lbl(inner, "—", fg="muted", font="smallbold")
            items.append((self.dock_lat, 2))
            self.dock_chat = RoundButton(inner, "chat", kind="primary", w=44, h=44, r=12, icon_px=20,
                                         command=lambda: self.toggle_chat(True))
            items.append((self.dock_chat.cv, 6))
            for ic, kind, cmd in (("phone", "soft", lambda: (self.toggle_chat(True), self.panel._call(False))),
                                  ("folder", "soft", self.open_files),
                                  ("fullscreen", "soft", self.toggle_full),
                                  ("power", "danger_soft", self.disconnect),
                                  ("chevron-left", "ghost", lambda: self.toggle_chat(True))):
                items.append((RoundButton(inner, ic, kind=kind, w=44, h=40 if kind == "ghost" else 44, r=12,
                                          command=cmd).cv, 3))
            for w, py in items:
                w.pack(pady=(py, 0))
            self.dock_win = d.create_window(30, 10, window=inner, anchor="n")
            inner.update_idletasks()
            h = inner.winfo_reqheight() + 20
            d.configure(height=h)
            d.bind("<Configure>", lambda e: self._dock_bg())
            T.on_change(self._dock_bg)
            self.toast = None

        def _dock_bg(self):
            try:
                d = self.dock
                h = int(d.cget("height"))
                d.delete("bg")
                d.create_image(0, 0, anchor="nw", image=shape_img(60, h, 18, T.c("card"), T.c("border"), 1), tags="bg")
                d.tag_lower("bg")
                d.configure(bg=T.c("viewer"))
            except tk.TclError:
                pass

        def toggle_chat(self, show=None):
            show = (not self.panel_shown) if show is None else show
            if show == self.panel_shown and (show or self.dock.winfo_ismapped()):
                return
            self.panel_shown = show
            if show:
                self.dock.place_forget()
                self._hide_toast()
                self.panel.frame.pack(side="right", fill="y", before=self.canvas)
                self.panel.seen()
                if self.info.get("chat"):
                    self.panel.entry.focus_set()
            else:
                self.panel.frame.pack_forget()
                self.dock.place(relx=1.0, x=-14, rely=0.5, anchor="e")
                self.dock.tk.call("raise", self.dock._w)
                self.canvas.focus_set()
            self.app.cfg["panel_open"] = show
            self.dirty = True

        def _on_unread(self, n, ev=None):
            if n == -1:                                   # สายเรียกเข้า → เปิดแผงให้เห็นปุ่มรับสาย
                self.toggle_chat(True)
                return
            self.dock_chat.configure(badge=n)
            if n and ev is not None and not self.panel_shown:
                self._show_toast(ev)

        def _show_toast(self, ev):
            self._hide_toast()
            t = self.toast = T.track(tk.Frame(self.body, bd=0, highlightthickness=1), bg="card")
            t.configure(highlightbackground=T.c("border"))
            row = box(t)
            row.pack(padx=14, pady=12)
            avatar(row, self.peer_name, 34, dot=False).pack(side="left", anchor="n")
            col = box(row)
            col.pack(side="left", padx=(10, 0))
            lbl(col, "%s  ·  %s" % (self.peer_name, tr("เมื่อสักครู่")), font="smallbold").pack(anchor="w")
            text = ev.get("text") if ev.get("ev") == "msg" else "📎 " + ev.get("name", "")
            text = (text or "").replace("\n", " ")
            lbl(col, text[:90] + ("…" if len(text) > 90 else ""), fg="text", font="small", wraplength=230,
                justify="left").pack(anchor="w")
            for w in (t, row, col) + tuple(col.winfo_children()):
                w.bind("<Button-1>", lambda e: self.toggle_chat(True))
            t.place(relx=1.0, x=-86, rely=0.5, anchor="e")
            t.lift()
            self.toast_job = self.win.after(5000, self._hide_toast)

        def _hide_toast(self):
            if self.toast is not None:
                try:
                    self.win.after_cancel(self.toast_job)
                    self.toast.destroy()
                except (tk.TclError, AttributeError, ValueError):
                    pass
                self.toast = None

        def _chat_poll(self):
            if self.closed:
                return
            latest_video = None
            try:
                for _ in range(200):
                    ev = self.cq.get_nowait()
                    if ev.get("ev") == "remote_video":       # เก็บเฉพาะภาพล่าสุด ลดภาระการวาด
                        latest_video = ev
                        continue
                    self.panel.on_event(ev, self.panel_shown)
            except queue.Empty:
                pass
            if latest_video is not None:
                self.panel.on_event(latest_video, self.panel_shown)
            self.win.after(40, self._chat_poll)

        def disconnect(self):
            if not self.closed:
                self.chan.close(tr("ตัดการเชื่อมต่อแล้ว"))
                self.destroy()

        def open_files(self):
            if not self.info.get("files"):
                if "v" not in self.info:
                    msg = (tr("เครื่องปลายทาง (%s) ใช้โปรแกรม NetRemote เวอร์ชันเก่า ที่ยังไม่รองรับการรับ-ส่งไฟล์\n\n"
                           "ให้อัปเดตโปรแกรมบนเครื่องปลายทางเป็นเวอร์ชันล่าสุด แล้วเชื่อมต่อใหม่") % self.info.get("name", ""))
                else:
                    msg = (tr("เครื่องปลายทาง (%s) ปิดการรับ-ส่งไฟล์ไว้\n\n"
                           "ที่เครื่องปลายทาง: แท็บ \"ให้เครื่องอื่นควบคุมเครื่องนี้\" → ติ๊ก \"อนุญาตให้รับ-ส่งไฟล์\" "
                           "แล้วเชื่อมต่อใหม่") % self.info.get("name", ""))
                messagebox.showinfo(APP, msg, parent=self.win)
                return
            if self.fw is None:
                self.fw = FileWindow(self)
            else:
                self.fw.show()

        def destroy(self):
            if self.closed:
                return
            self.closed = True
            self.files.close()
            try:
                self.call.close()
                self.chat.close()
            except Exception:
                pass
            try:
                self.win.destroy()
            except Exception:
                pass

    # ------------------------------------------------------------------
    class LocalPicker:
        """ตัวเลือกไฟล์/โฟลเดอร์ในเครื่องนี้ (ใช้แทนหน้าต่างของระบบบน macOS ซึ่งบางครั้งเปิดไม่ขึ้น)"""

        def __init__(self, parent, title, mode="files", initial=None):
            self.mode, self.result = mode, None
            self.cur = None
            self.entries = {}
            w = self.win = T.track(tk.Toplevel(parent), bg="bg")
            w.title(title)
            w.geometry("760x540")
            w.minsize(520, 380)
            try:
                w.transient(parent)
            except Exception:
                pass
            nav = ttk.Frame(w, padding=(10, 10, 10, 4))
            nav.pack(fill="x")
            ttk.Button(nav, text=tr("⬆ ขึ้น"), width=6, command=self.up).pack(side="left")
            home = os.path.expanduser("~")
            for label, sub in (("⌂ Home", ""), ("Desktop", "Desktop"), ("Documents", "Documents"),
                               ("Downloads", "Downloads")):
                p = os.path.join(home, sub) if sub else home
                if os.path.isdir(p):
                    ttk.Button(nav, text=label, command=lambda p=p: self.go(p)).pack(side="left", padx=(4, 0))
            if SYSTEM == "Darwin" and os.path.isdir("/Volumes"):
                ttk.Button(nav, text=tr("ไดรฟ์"), command=lambda: self.go("/Volumes")).pack(side="left", padx=(4, 0))
            self.path_var = tk.StringVar()
            pe = ttk.Entry(w, textvariable=self.path_var)
            pe.pack(fill="x", padx=10, pady=(2, 4))
            pe.bind("<Return>", lambda e: self.go(self.path_var.get().strip()))
            hint = (tr("เลือกได้หลายรายการ (กด ⌘/Ctrl หรือ Shift ค้าง) — เลือกโฟลเดอร์ได้ด้วย ดับเบิลคลิกโฟลเดอร์เพื่อเปิด")
                    if mode == "files" else tr("เปิดโฟลเดอร์ที่ต้องการ แล้วกด \"เลือกโฟลเดอร์นี้\" (หรือคลิกเลือกโฟลเดอร์ย่อย)"))
            ttk.Label(w, text=hint, style="Muted.TLabel", padding=(10, 0)).pack(fill="x")
            fr = ttk.Frame(w, padding=(10, 4, 10, 0))
            fr.pack(fill="both", expand=True)
            t = self.tree = ttk.Treeview(fr, columns=("name", "size", "mtime"), show="headings",
                                         selectmode="extended" if mode == "files" else "browse")
            for c, txt, wd, st in (("name", tr("ชื่อ"), 400, True), ("size", tr("ขนาด"), 100, False),
                                   ("mtime", tr("แก้ไขล่าสุด"), 150, False)):
                t.heading(c, text=txt)
                t.column(c, width=wd, stretch=st, anchor="e" if c == "size" else "w")
            sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview)
            t.configure(yscrollcommand=sb.set)
            t.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            t.bind("<Double-1>", self.on_double)
            bot = ttk.Frame(w, padding=10)
            bot.pack(fill="x")
            self.info_var = tk.StringVar()
            ttk.Label(bot, textvariable=self.info_var, style="Muted.TLabel").pack(side="left")
            ttk.Button(bot, text=tr("ยกเลิก"), command=w.destroy).pack(side="right")
            ttk.Button(bot, text=tr("เลือก") if mode == "files" else tr("เลือกโฟลเดอร์นี้"), style="Accent.TButton",
                       command=self.choose).pack(side="right", padx=6)
            t.bind("<<TreeviewSelect>>", lambda e: self._sel_info())
            self.go(initial if initial and os.path.isdir(initial) else home)
            w.protocol("WM_DELETE_WINDOW", w.destroy)
            w.lift()
            w.focus_force()
            try:
                w.grab_set()
            except Exception:
                pass
            w.wait_window()

        def go(self, path):
            path = os.path.abspath(os.path.expanduser(path or "~"))
            try:
                items = sorted(os.scandir(path), key=lambda e: (not e.is_dir(), e.name.lower()))
            except OSError as e:
                messagebox.showerror(APP, tr("เปิดโฟลเดอร์ไม่ได้: %s") % err_text(e), parent=self.win)
                return
            self.cur = path
            self.path_var.set(path)
            self.tree.delete(*self.tree.get_children(""))
            self.entries.clear()
            n = 0
            for e in items:
                if e.name.startswith("."):
                    continue
                try:
                    isdir = e.is_dir()
                    st = e.stat()
                except OSError:
                    continue
                if self.mode == "folder" and not isdir:
                    continue
                iid = "p%d" % n
                n += 1
                self.entries[iid] = (e.path, isdir)
                self.tree.insert("", "end", iid=iid, values=(("📁  " if isdir else "📄  ") + e.name,
                                                             "" if isdir else fmt_size(st.st_size),
                                                             datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")))
            self._sel_info()

        def up(self):
            if self.cur:
                parent = os.path.dirname(self.cur)
                if parent != self.cur:
                    self.go(parent)

        def _sel_info(self):
            sel = [self.entries[i] for i in self.tree.selection() if i in self.entries]
            if sel:
                self.info_var.set(tr("เลือก %d รายการ") % len(sel))
            else:
                self.info_var.set(self.cur or "")

        def on_double(self, e=None):
            sel = self.tree.selection()
            if not sel or sel[0] not in self.entries:
                return
            path, isdir = self.entries[sel[0]]
            if isdir:
                self.go(path)
            elif self.mode == "files":
                self.result = [path]
                self.win.destroy()

        def choose(self):
            sel = [self.entries[i][0] for i in self.tree.selection() if i in self.entries]
            if self.mode == "folder":
                self.result = sel[0] if sel else self.cur
            else:
                if not sel:
                    messagebox.showinfo(APP, tr("คลิกเลือกไฟล์หรือโฟลเดอร์ก่อน"), parent=self.win)
                    return
                self.result = sel
            self.win.destroy()

    def pick_files(parent, title):
        """คืนรายการ path ที่เลือก (ไฟล์และ/หรือโฟลเดอร์)"""
        if SYSTEM != "Darwin":
            try:
                return list(filedialog.askopenfilenames(parent=parent, title=title) or [])
            except Exception as e:
                log_error(e)
        return LocalPicker(parent, title, "files").result or []

    def pick_folder(parent, title, initial=None):
        if SYSTEM != "Darwin":
            try:
                return filedialog.askdirectory(parent=parent, title=title, initialdir=initial) or ""
            except Exception as e:
                log_error(e)
        return LocalPicker(parent, title, "folder", initial).result or ""

    # ------------------------------------------------------------------
    # ชุดเครื่องมือ UI แบบโมเดิร์น: ไอคอนเส้น, ปุ่มกลม/แคปซูล, สวิตช์, กรอบมุมมน (วาดด้วย PIL ให้คมทุกจอ)
    # ------------------------------------------------------------------
    from PIL import ImageDraw as _IDraw
    _ICONS = {}
    _SHAPES = {}
    SS = 4                                            # วาดใหญ่ 4 เท่าแล้วย่อ → ขอบเนียน

    def _hex(c):
        c = c.lstrip("#")
        return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))

    def _draw_icon(name, px, color):
        S = 64
        im = Image.new("RGBA", (S * SS, S * SS), (0, 0, 0, 0))
        d = _IDraw.Draw(im)
        col = _hex(color) + (255,)
        w = int(5.2 * SS)
        k = SS

        def L(*pts):
            d.line([(x * k, y * k) for x, y in pts], fill=col, width=w, joint="curve")
            for x, y in (pts[0], pts[-1]):
                d.ellipse((x * k - w / 2, y * k - w / 2, x * k + w / 2, y * k + w / 2), fill=col)

        def R(x0, y0, x1, y1, r, fill=False):
            if fill:
                d.rounded_rectangle((x0 * k, y0 * k, x1 * k, y1 * k), r * k, fill=col)
            else:
                d.rounded_rectangle((x0 * k, y0 * k, x1 * k, y1 * k), r * k, outline=col, width=w)

        def A(x0, y0, x1, y1, a0, a1):
            d.arc((x0 * k, y0 * k, x1 * k, y1 * k), a0, a1, fill=col, width=w)

        def P(pts, fill=True):
            if fill:
                d.polygon([(x * k, y * k) for x, y in pts], fill=col)
            else:
                d.line([(x * k, y * k) for x, y in pts + [pts[0]]], fill=col, width=w, joint="curve")

        def C(cx, cy, r, fill=True):
            if fill:
                d.ellipse(((cx - r) * k, (cy - r) * k, (cx + r) * k, (cy + r) * k), fill=col)
            else:
                d.ellipse(((cx - r) * k, (cy - r) * k, (cx + r) * k, (cy + r) * k), outline=col, width=w)

        if name == "chat":
            R(8, 10, 56, 46, 14)
            P([(18, 44), (16, 56), (30, 45)])
        elif name in ("phone", "hangup"):
            ph = Image.new("RGBA", im.size, (0, 0, 0, 0))
            dp = _IDraw.Draw(ph)
            # หูโทรศัพท์: โค้งหนาด้านบน + ปลายสองข้างชี้ลง (= วางสาย) แล้วหมุน 45° (= โทร)
            dp.arc((6 * k, 14 * k, 58 * k, 66 * k), 198, 342, fill=col, width=int(10 * SS))
            for cx in (11, 53):
                dp.rounded_rectangle(((cx - 8) * k, 27 * k, (cx + 8) * k, 42 * k), 5 * k, fill=col)
            if name == "phone":
                ph = ph.rotate(45, resample=Image.BICUBIC, center=(32 * k, 32 * k))
            else:
                ph = ph.transform(ph.size, Image.AFFINE, (1, 0, 0, 0, 1, -4 * k), resample=Image.BICUBIC)
            im = Image.alpha_composite(im, ph)
        elif name in ("video", "video-off"):
            R(6, 18, 42, 46, 7)
            P([(46, 28), (58, 20), (58, 44), (46, 36)])
            if name == "video-off":
                L((8, 8), (56, 56))
        elif name == "chevron-right":
            L((24, 14), (40, 32), (24, 50))
        elif name == "chevron-left":
            L((40, 14), (24, 32), (40, 50))
        elif name == "minus":
            L((16, 32), (48, 32))
        elif name == "folder":
            P([(8, 16), (26, 16), (31, 22), (56, 22), (56, 50), (8, 50)], fill=False)
        elif name == "text":
            L((14, 18), (14, 12), (50, 12), (50, 18))
            L((32, 12), (32, 52))
            L((24, 52), (40, 52))
        elif name == "keyboard":
            R(6, 18, 58, 46, 6)
            for x in (16, 26, 36, 46):
                C(x, 27, 2.6)
            L((20, 37), (44, 37))
        elif name == "fullscreen":
            L((10, 22), (10, 10), (22, 10))
            L((42, 10), (54, 10), (54, 22))
            L((10, 42), (10, 54), (22, 54))
            L((42, 54), (54, 54), (54, 42))
        elif name == "power":
            A(12, 14, 52, 54, -50, 230)
            L((32, 8), (32, 32))
        elif name in ("mic", "mic-off"):
            R(24, 6, 40, 38, 8)
            A(14, 16, 50, 46, 0, 180)
            L((32, 46), (32, 56))
            if name == "mic-off":
                L((10, 8), (54, 56))
        elif name in ("speaker", "speaker-off"):
            P([(8, 24), (18, 24), (32, 12), (32, 52), (18, 40), (8, 40)])
            if name == "speaker":
                A(28, 20, 48, 44, -55, 55)
                A(26, 10, 58, 54, -55, 55)
            else:
                L((40, 24), (56, 40))
                L((56, 24), (40, 40))
        elif name == "plus":
            L((32, 12), (32, 52))
            L((12, 32), (52, 32))
        elif name == "send":
            P([(8, 30), (56, 8), (40, 56), (32, 36)])
        elif name == "download":
            L((32, 8), (32, 40))
            L((18, 28), (32, 42), (46, 28))
            L((12, 54), (52, 54))
        elif name == "x":
            L((16, 16), (48, 48))
            L((48, 16), (16, 48))
        elif name == "file":
            P([(14, 6), (38, 6), (52, 20), (52, 58), (14, 58)], fill=False)
            L((38, 6), (38, 20), (52, 20))
        elif name == "image":
            R(6, 10, 58, 54, 7)
            C(22, 25, 5)
            P([(10, 50), (28, 32), (38, 42), (44, 36), (56, 48), (56, 50)])
        elif name == "eye":
            A(4, 14, 60, 50, 200, 340)
            A(4, 14, 60, 50, 20, 160)
            C(32, 32, 7)
        im = im.resize((px, px), Image.LANCZOS)
        return im

    def icon(name, px=18, color="#1B1D26"):
        key = (name, px, color)
        if key not in _ICONS:
            _ICONS[key] = ImageTk.PhotoImage(_draw_icon(name, px * 2 if px <= 24 else px, color).resize(
                (px, px), Image.LANCZOS))
        return _ICONS[key]

    def shape_img(w, h, r, fill, outline=None, ow=1):
        """สี่เหลี่ยมมุมมน / วงกลม (r = h/2) ขอบเนียน"""
        key = (w, h, r, fill, outline, ow)
        if key not in _SHAPES:
            im = Image.new("RGBA", (w * SS, h * SS), (0, 0, 0, 0))
            d = _IDraw.Draw(im)
            box_ = (0, 0, w * SS - 1, h * SS - 1)
            d.rounded_rectangle(box_, r * SS, fill=_hex(fill) + (255,),
                                outline=(_hex(outline) + (255,)) if outline else None, width=ow * SS if outline else 0)
            _SHAPES[key] = ImageTk.PhotoImage(im.resize((w, h), Image.LANCZOS))
        return _SHAPES[key]

    def rounded_photo(pil, r):
        """รูปภาพมุมมน"""
        pil = pil.convert("RGBA")
        m = Image.new("L", (pil.width * SS, pil.height * SS), 0)
        _IDraw.Draw(m).rounded_rectangle((0, 0, pil.width * SS - 1, pil.height * SS - 1), r * SS, fill=255)
        pil.putalpha(m.resize(pil.size, Image.LANCZOS))
        return ImageTk.PhotoImage(pil)

    KIND = {   # ชนิดปุ่ม → (พื้น, พื้นตอนชี้, สีไอคอน/ตัวอักษร) เป็นชื่อสีในธีม หรือ hex
        "soft": ("subtle", "hover", "text"),
        "tile": ("card", "hover", "text"),
        "primary": ("accent", "accent_hover", "accent_fg"),
        "danger": ("danger", "danger_hover", "#FFFFFF"),
        "danger_soft": ("danger_bg", "hover", "danger"),
        "success": ("#16A34A", "#15803D", "#FFFFFF"),
        "dark": ("#2A2F40", "#363C52", "#FFFFFF"),
        "ghost": (None, "hover", "muted"),
        "outline": ("card", "hover", "text"),
    }

    def tcol(c):
        return c if (c or "").startswith("#") else T.c(c)

    class RoundButton:
        """ปุ่มกลม / แคปซูล / ไทล์ (ไอคอน + ข้อความ) วาดบน Canvas"""

        def __init__(self, parent, icon_name=None, text="", kind="soft", w=38, h=38, r=None, command=None,
                     bg="card", layout="row", icon_px=18, font="smallbold", badge=0):
            self.parent_bg, self.kind, self.icon_name, self.text = bg, kind, icon_name, text
            self.w, self.h, self.r = w, h, (h // 2 if r is None else r)
            self.layout, self.icon_px, self.font, self.command = layout, icon_px, font, command
            self.badge = badge
            self.hover = False
            self.enabled = True
            self.cv = tk.Canvas(parent, width=w, height=h, highlightthickness=0, bd=0, cursor="hand2")
            self.cv.bind("<Enter>", lambda e: self._set_hover(True))
            self.cv.bind("<Leave>", lambda e: self._set_hover(False))
            self.cv.bind("<ButtonRelease-1>", self._click)
            T.on_change(self.draw)
            self.draw()

        def pack(self, **kw):
            self.cv.pack(**kw)
            return self

        def grid(self, **kw):
            self.cv.grid(**kw)
            return self

        def place(self, **kw):
            self.cv.place(**kw)
            return self

        def pack_forget(self):
            self.cv.pack_forget()

        def destroy(self):
            self.cv.destroy()

        def _set_hover(self, v):
            self.hover = v
            self.draw()

        def _click(self, e):
            if self.enabled and self.command and 0 <= e.x <= self.w and 0 <= e.y <= self.h:
                self.command()

        def configure(self, **kw):
            for k, v in kw.items():
                setattr(self, {"icon": "icon_name"}.get(k, k), v)
            self.draw()

        def set_enabled(self, on):
            self.enabled = bool(on)
            self.cv.configure(cursor="hand2" if on else "arrow")
            self.draw()

        def draw(self):
            try:
                c = self.cv
                c.delete("all")
            except tk.TclError:
                return
            pbg = tcol(self.parent_bg)
            c.configure(bg=pbg)
            base, hov, fg = KIND.get(self.kind, KIND["soft"])
            fill = tcol(hov if self.hover and self.enabled else base) if (base or self.hover) else None
            fgc = tcol(fg)
            if not self.enabled:
                fgc = T.c("muted")
            if fill:
                c.create_image(0, 0, anchor="nw", image=shape_img(self.w, self.h, self.r, fill,
                                                                  T.c("border") if self.kind == "outline" else None))
            ic = icon(self.icon_name, self.icon_px, fgc) if self.icon_name else None
            f = T.f[self.font]
            if self.layout == "column" and ic and self.text:
                c.create_image(self.w / 2, self.h / 2 - 8, image=ic)
                c.create_text(self.w / 2, self.h / 2 + 13, text=self.text, fill=fgc, font=f)
            elif ic and self.text:
                tw = f.measure(self.text)
                x0 = (self.w - (self.icon_px + 7 + tw)) / 2
                c.create_image(x0 + self.icon_px / 2, self.h / 2, image=ic)
                c.create_text(x0 + self.icon_px + 7, self.h / 2, text=self.text, fill=fgc, font=f, anchor="w")
            elif ic:
                c.create_image(self.w / 2, self.h / 2, image=ic)
            else:
                c.create_text(self.w / 2, self.h / 2, text=self.text, fill=fgc, font=f)
            if self.badge:
                t = str(self.badge if self.badge < 100 else "99+")
                bw = max(18, 8 + f.measure(t))
                c.create_image(self.w - bw + 2, -2, anchor="nw", image=shape_img(bw, 18, 9, T.c("danger"), pbg, 2))
                c.create_text(self.w - bw / 2 + 2, 7, text=t, fill="#FFFFFF", font=T.f["smallbold"])

    class Switch:
        """สวิตช์เปิด/ปิด + ข้อความ"""

        def __init__(self, parent, text, var, command=None, bg="card"):
            self.var, self.command, self.bg, self.text = var, command, bg, text
            self.enabled = True
            f = T.f["smallbold"]
            self.w = 34 + 8 + f.measure(text) + 4
            self.cv = tk.Canvas(parent, width=self.w, height=22, highlightthickness=0, bd=0, cursor="hand2")
            self.cv.bind("<ButtonRelease-1>", self._click)
            var.trace_add("write", lambda *a: self.draw())
            T.on_change(self.draw)
            self.draw()

        def pack(self, **kw):
            self.cv.pack(**kw)
            return self

        def _click(self, e):
            if not self.enabled:
                return
            self.var.set(not self.var.get())
            if self.command:
                self.command()

        def set_enabled(self, on):
            self.enabled = on
            self.draw()

        def draw(self):
            try:
                c = self.cv
                c.delete("all")
            except tk.TclError:
                return
            c.configure(bg=tcol(self.bg))
            on = bool(self.var.get())
            track = T.c("accent") if on and self.enabled else T.c("border")
            c.create_image(0, 2, anchor="nw", image=shape_img(34, 20, 10, track))
            c.create_image(16 if on else 2, 4, anchor="nw", image=shape_img(16, 16, 8, "#FFFFFF"))
            c.create_text(42, 11, text=self.text, anchor="w", font=T.f["smallbold"],
                          fill=T.c("text") if self.enabled else T.c("muted"))

    def avatar_img(name, px=42, dot=True, ring=0):
        """วงกลมตัวอักษรแรกของชื่อ + จุดสถานะออนไลน์"""
        ch = (name.strip()[:1] or "?").upper()
        palette = [("#ECE7FF", "#5B3AE6"), ("#E0F2FE", "#0369A1"), ("#DCFCE7", "#15803D"), ("#FEF3C7", "#B45309")]
        bg, fg = palette[sum(map(ord, name or "?")) % len(palette)]
        key = ("avatar", ch, px, dot, ring, bg, T.c("card"))
        if key in _SHAPES:
            return _SHAPES[key]
        S = (px + ring * 2) * SS
        im = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        d = _IDraw.Draw(im)
        for i in range(ring, 0, -1):
            a = int(40 * (ring - i + 1) / ring)
            d.ellipse((0 + (ring - i) * SS, 0 + (ring - i) * SS, S - (ring - i) * SS, S - (ring - i) * SS),
                      fill=_hex(bg) + (a,))
        o = ring * SS
        d.ellipse((o, o, o + px * SS, o + px * SS), fill=_hex(bg) + (255,))
        if dot:
            r = px * SS * 0.14
            cx, cy = o + px * SS - r - SS, o + px * SS - r - SS
            d.ellipse((cx - r - 2 * SS, cy - r - 2 * SS, cx + r + 2 * SS, cy + r + 2 * SS), fill=_hex(T.c("card")) + (255,))
            d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=_hex("#16A34A") + (255,))
        im = im.resize((px + ring * 2, px + ring * 2), Image.LANCZOS)
        ph = ImageTk.PhotoImage(im)
        _SHAPES[key] = (ph, ch, fg)
        return _SHAPES[key]

    def avatar(parent, name, px=42, bg="card", dot=True, ring=0):
        ph, ch, fg = avatar_img(name, px, dot, ring)
        size = px + ring * 2
        c = tk.Canvas(parent, width=size, height=size, highlightthickness=0, bd=0, bg=tcol(bg))
        c.create_image(0, 0, anchor="nw", image=ph)
        c.create_text(size / 2, size / 2, text=ch, fill=fg,
                      font=(T.f["bold"].actual("family"), max(10, int(px * 0.38)), "bold"))
        return c

    # ------------------------------------------------------------------
    # แผงด้านข้าง: (ผู้ควบคุม) ปุ่มควบคุมการรีโมท + แชท + โทร  /  (เครื่องปลายทาง) แชท + โทร
    # ------------------------------------------------------------------
    def show_in_folder(p):
        try:
            if SYSTEM == "Darwin":
                subprocess.Popen(["open", "-R", p])
            elif SYSTEM == "Windows":
                subprocess.Popen(["explorer", "/select,", os.path.normpath(p)])
            else:
                open_path(os.path.dirname(p))
        except Exception:
            pass

    EXT_COLOR = {"pdf": ("#FDECEC", "#DC2626"), "doc": ("#E0ECFF", "#2563EB"), "docx": ("#E0ECFF", "#2563EB"),
                 "xls": ("#DCFCE7", "#15803D"), "xlsx": ("#DCFCE7", "#15803D"), "csv": ("#DCFCE7", "#15803D"),
                 "zip": ("#FEF3C7", "#B45309"), "rar": ("#FEF3C7", "#B45309"), "ppt": ("#FFEDD5", "#C2410C"),
                 "pptx": ("#FFEDD5", "#C2410C")}

    class ChatPanel:
        CALL_BG = "#12141C"

        def __init__(self, parent, chat, call, peer, mode="controller", width=340, on_hide=None, viewer=None,
                     chat_ok=True, subtitle=""):
            self.chat, self.call, self.peer, self.mode = chat, call, peer, mode
            self.width, self.on_hide, self.viewer, self.chat_ok = width, on_hide, viewer, chat_ok
            self.items = {}                 # id → ข้อมูลข้อความ/ไฟล์ที่แสดงอยู่
            self.imgs = []
            self.unread = 0
            self.unread_ids = []
            self.on_unread = None
            self.visible = True
            self.remote_photo = self.self_photo = None
            self.last_day = None
            self.typing_until = 0
            f = self.frame = T.track(tk.Frame(parent, width=width, bd=0, highlightthickness=0), bg="card")
            f.pack_propagate(False)
            if mode == "controller":
                T.track(tk.Frame(f, width=1, bd=0), bg="border").pack(side="left", fill="y")
            body = self.body = box(f)
            body.pack(side="left", fill="both", expand=True)

            # --- หัว ---
            head = box(body)
            head.pack(fill="x", padx=(16, 10), pady=(14, 12))
            avatar(head, peer, 42).pack(side="left")
            names = box(head)
            names.pack(side="left", fill="x", expand=True, padx=(12, 6))
            lbl(names, peer, font="bold").pack(anchor="w")
            self.sub = lbl(names, subtitle, fg="muted", font="small")
            self.sub.pack(anchor="w")
            if on_hide:
                RoundButton(head, "chevron-right" if mode == "controller" else "minus", kind="ghost", w=30, h=38,
                            r=10, command=on_hide).pack(side="right")
            self.vbtn = RoundButton(head, "video", command=lambda: self._call(True)).pack(side="right", padx=(6, 4))
            self.abtn = RoundButton(head, "phone", command=lambda: self._call(False)).pack(side="right")

            # --- ปุ่มควบคุมการรีโมท (เฉพาะผู้ควบคุม) ---
            if mode == "controller" and viewer is not None:
                self._build_controls(body, viewer)

            # --- พื้นที่โทร ---
            self.callbox = tk.Frame(body, bd=0, bg=self.CALL_BG)
            self._build_call()

            # --- ข้อความ ---
            T.track(tk.Frame(body, height=1, bd=0), bg="border").pack(fill="x")
            mid = box(body, bg="bg")
            mid.pack(fill="both", expand=True)
            self.cv = T.track(tk.Canvas(mid, highlightthickness=0, bd=0), bg="bg")
            sb = ttk.Scrollbar(mid, orient="vertical", command=self.cv.yview)
            self.cv.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            self.cv.pack(side="left", fill="both", expand=True)
            self.inner = box(self.cv, bg="bg")
            self.win_id = self.cv.create_window(0, 0, window=self.inner, anchor="nw")
            self.inner.bind("<Configure>", lambda e: self.cv.configure(scrollregion=self.cv.bbox("all")))
            self.cv.bind("<Configure>", lambda e: self.cv.itemconfigure(self.win_id, width=e.width))
            for w in (self.cv, self.inner):
                w.bind("<MouseWheel>", self._wheel)
                w.bind("<Button-4>", lambda e: self.cv.yview_scroll(-2, "units"))
                w.bind("<Button-5>", lambda e: self.cv.yview_scroll(2, "units"))
            self.empty = lbl(self.inner, tr("ยังไม่มีข้อความ\nพิมพ์ข้อความ หรือส่งไฟล์ รูป วีดีโอได้ที่ด้านล่าง")
                             if chat_ok else tr("เครื่องปลายทางใช้โปรแกรมเวอร์ชันเก่าที่ยังไม่มีแชท"),
                             fg="muted", bg="bg", font="small", justify="center", anchor="center",
                             wraplength=width - 60)
            self.empty.pack(fill="x", pady=40)
            self.typing_row = box(self.inner, bg="bg")
            tc = tk.Canvas(self.typing_row, width=58, height=34, highlightthickness=0, bd=0)
            self.typing_cv = tc
            T.on_change(self._draw_typing)
            self._draw_typing()
            tc.pack(side="left", padx=14, pady=(2, 8))

            # --- ช่องพิมพ์ (ติดด้านล่างเสมอ แม้กำลังโทร) ---
            comp = box(body)
            comp.pack(side="bottom", fill="x", padx=12, pady=(10, 14), before=mid)
            T.track(tk.Frame(body, height=1, bd=0), bg="border").pack(side="bottom", fill="x", before=mid)
            self.plus = RoundButton(comp, "plus", kind="outline", w=42, h=42, command=self._attach_menu).pack(side="left")
            self.send_btn = RoundButton(comp, "send", kind="primary", w=42, h=42, icon_px=17,
                                        command=self._send).pack(side="right")
            pill = self.pill = tk.Canvas(comp, height=42, highlightthickness=0, bd=0)
            pill.pack(side="left", fill="x", expand=True, padx=8)
            self.entry_var = tk.StringVar()
            self.placeholder = tr("พิมพ์ข้อความ…")
            e = self.entry = tk.Entry(pill, textvariable=self.entry_var, bd=0, highlightthickness=0, relief="flat",
                                      font=T.f["base"])
            self.pill_win = pill.create_window(16, 21, window=e, anchor="w")
            self.focused = False
            self.ph_on = False
            e.bind("<FocusIn>", lambda ev: self._pill_focus(True))
            e.bind("<FocusOut>", lambda ev: self._pill_focus(False))
            e.bind("<Return>", lambda ev: self._send())
            e.bind("<KeyRelease>", lambda ev: self.chat.send_typing()
                   if self.chat_ok and not self.ph_on and ev.keysym != "Return" else None)
            pill.bind("<Configure>", lambda ev: self._draw_pill())
            pill.bind("<Button-1>", lambda ev: e.focus_set())
            T.on_change(self._draw_pill)
            if not chat_ok:
                for b in (self.plus, self.send_btn, self.abtn, self.vbtn):
                    b.set_enabled(False)
                e.configure(state="disabled")
            self._tick()

        # ================= ปุ่มควบคุมการรีโมท =================
        def _build_controls(self, body, v):
            outer = box(body)
            outer.pack(fill="x", padx=12, pady=(0, 12))
            cb = T.track(tk.Frame(outer, bd=0, highlightthickness=0), bg="subtle")
            cb.pack(fill="x")
            r1 = box(cb, bg="subtle")
            r1.pack(fill="x", padx=10, pady=(10, 8))
            qb = ttk.Combobox(r1, values=[q[0] for q in QUALITY], textvariable=v.q_var, state="readonly", width=7)
            qb.pack(side="left")
            qb.bind("<<ComboboxSelected>>", lambda e: v._quality_changed())
            if len(v.mvals) > 1:
                mb = ttk.Combobox(r1, values=v.mvals, textvariable=v.mon_var, state="readonly", width=7)
                mb.pack(side="left", padx=(6, 0))
                mb.bind("<<ComboboxSelected>>", lambda e: v.request(full=True))
            Switch(r1, "⌘↔Ctrl", v.swap_var, bg="subtle").pack(side="right")
            sw = Switch(r1, tr("ควบคุม"), v.ctrl_var, command=v._release_all, bg="subtle").pack(side="right", padx=(0, 10))
            if not v.can_control:
                sw.set_enabled(False)
            r2 = box(cb, bg="subtle")
            r2.pack(fill="x", padx=10, pady=(0, 10))
            tw = max(46, int((self.width - 24 - 20 - 4 * 6) / 5))
            for i, (ic, txt, kind, cmd) in enumerate((
                    ("folder", tr("ไฟล์"), "tile", v.open_files),
                    ("text", tr("พิมพ์"), "tile", v.send_text),
                    ("keyboard", tr("ปล่อยปุ่ม"), "tile", v._release_all),
                    ("fullscreen", tr("เต็มจอ"), "tile", v.toggle_full),
                    ("power", tr("ตัดสาย"), "danger_soft", v.disconnect))):
                RoundButton(r2, ic, text=txt, kind=kind, w=tw, h=56, r=12, layout="column", bg="subtle",
                            font="small", command=cmd).grid(row=0, column=i, padx=(0 if i == 0 else 6, 0))

        def set_latency(self, text, color):
            self.sub.configure(text=text, fg=T.c(color))

        # ================= ช่องพิมพ์ =================
        def _draw_pill(self):
            try:
                c = self.pill
                w = max(60, c.winfo_width())
            except tk.TclError:
                return
            c.delete("bg")
            c.configure(bg=T.c("card"))
            if self.focused:
                c.create_image(0, 0, anchor="nw", image=shape_img(w, 42, 21, T.c("sel")), tags="bg")
                c.create_image(3, 3, anchor="nw", image=shape_img(w - 6, 36, 18, T.c("card"), T.c("accent"), 2), tags="bg")
            else:
                c.create_image(0, 0, anchor="nw", image=shape_img(w, 42, 21, T.c("card"), T.c("border"), 1), tags="bg")
            c.tag_lower("bg")
            c.itemconfigure(self.pill_win, width=w - 32)
            self.entry.configure(bg=T.c("card"), fg=T.c("text"), insertbackground=T.c("text"),
                                 disabledbackground=T.c("card"))
            self._placeholder()

        def _pill_focus(self, on):
            self.focused = on
            if on and self.ph_on:
                self.ph_on = False
                self.entry.delete(0, "end")
            self._draw_pill()

        def _placeholder(self):
            """ข้อความจาง ๆ ในช่องพิมพ์ตอนว่าง"""
            if not self.focused and not self.ph_on and not self.entry_var.get():
                self.ph_on = True
                self.entry.insert(0, self.placeholder)
            self.entry.configure(fg=T.c("muted") if self.ph_on else T.c("text"))

        def _send(self):
            text = self.entry_var.get()
            if text.strip() and self.chat_ok and not self.ph_on:
                self.chat.send_text(text)
                self.entry_var.set("")

        def _attach_menu(self):
            m = tk.Menu(self.frame, tearoff=0)
            m.add_command(label="  " + tr("ไฟล์") + "…", command=lambda: self._attach("file"))
            m.add_command(label="  " + tr("รูป") + "…", command=lambda: self._attach("image"))
            m.add_command(label="  " + tr("วีดีโอ") + "…", command=lambda: self._attach("video"))
            x, y = self.plus.cv.winfo_rootx(), self.plus.cv.winfo_rooty()
            try:
                m.tk_popup(x, y - 90)
            finally:
                m.grab_release()

        def _attach(self, kind):
            title = {"file": tr("เลือกไฟล์ที่จะส่ง"), "image": tr("เลือกรูปที่จะส่ง"), "video": tr("เลือกวีดีโอที่จะส่ง")}[kind]
            paths = []
            if SYSTEM != "Darwin":
                types = {"image": [(tr("รูปภาพ"), " ".join("*" + x for x in IMAGE_EXT)), (tr("ทุกไฟล์"), "*")],
                         "video": [(tr("วีดีโอ"), " ".join("*" + x for x in VIDEO_EXT)), (tr("ทุกไฟล์"), "*")],
                         "file": [(tr("ทุกไฟล์"), "*")]}[kind]
                try:
                    paths = list(filedialog.askopenfilenames(parent=self.frame, title=title, filetypes=types) or [])
                except Exception:
                    paths = []
            else:
                paths = LocalPicker(self.frame.winfo_toplevel(), title, "files").result or []
            for p in paths:
                if os.path.isfile(p):
                    self.chat.send_file(p)

        # ================= ข้อความ =================
        def _wheel(self, e):
            if abs(e.delta) >= 120:
                self.cv.yview_scroll(int(-e.delta / 120), "units")
            else:
                self.cv.yview_scroll(-1 if e.delta > 0 else 1, "units")

        def _scroll_end(self):
            self.inner.update_idletasks()
            self.cv.configure(scrollregion=self.cv.bbox("all"))
            self.cv.yview_moveto(1.0)

        def _row(self, ts=None):
            if self.empty is not None:
                self.empty.destroy()
                self.empty = None
            day = time.strftime("%Y%m%d", time.localtime(ts or time.time()))
            if day != self.last_day:
                self.last_day = day
                today = day == time.strftime("%Y%m%d")
                txt = tr("วันนี้") if today else time.strftime("%d/%m/%Y", time.localtime(ts or time.time()))
                dv = box(self.inner, bg="bg")
                dv.pack(fill="x", pady=(12, 4), before=self.typing_row if self.typing_row.winfo_ismapped() else None)
                ccv = tk.Canvas(dv, height=22, highlightthickness=0, bd=0, bg=T.c("bg"))
                f = T.f["smallbold"]
                wd = f.measure(txt) + 20
                ccv.configure(width=wd)
                ccv.create_image(0, 1, anchor="nw", image=shape_img(wd, 20, 10, T.c("subtle")))
                ccv.create_text(wd / 2, 11, text=txt, fill=T.c("muted"), font=f)
                ccv.pack()
            row = box(self.inner, bg="bg")
            row.pack(fill="x", padx=12, pady=4, before=self.typing_row if self.typing_row.winfo_ismapped() else None)
            return row

        def _bubble(self, parent, text, mine):
            f = T.f["base"]
            maxw = self.width - 120
            c = tk.Canvas(parent, highlightthickness=0, bd=0, bg=T.c("bg"))
            tid = c.create_text(13, 9, text=text, anchor="nw", width=maxw, font=f,
                                fill=T.c("accent_fg") if mine else T.c("text"))
            x0, y0, x1, y1 = c.bbox(tid)
            w, h = max(36, x1 + 13), max(34, y1 + 9)
            c.configure(width=w, height=h)
            if mine:
                bgc = T.c("accent")
                c.create_image(0, 0, anchor="nw", image=shape_img(w, h, 16, bgc))
                c.create_rectangle(w - 12, h - 12, w, h, fill=bgc, outline=bgc)      # มุมล่างขวาแหลม = ฝั่งเรา
            else:
                c.create_image(0, 0, anchor="nw", image=shape_img(w, h, 16, T.c("card"), T.c("border"), 1))
            c.tag_raise(tid)
            return c

        def _meta(self, parent, mine, text):
            m = lbl(parent, text, fg="muted", bg="bg", font="small")
            m.pack(anchor="e" if mine else "w", padx=4, pady=(2, 0))
            return m

        def _stamp(self, ts):
            return time.strftime("%H:%M", time.localtime(ts or time.time()))

        def add_msg(self, m):
            mine = m.get("mine")
            row = self._row(m.get("t"))
            col = box(row, bg="bg")
            col.pack(side="right" if mine else "left")
            self._bubble(col, m.get("text", ""), mine).pack(anchor="e" if mine else "w")
            meta = self._meta(col, mine, self._stamp(m.get("t")) if mine else
                              "%s · %s" % (m.get("name") or self.peer, self._stamp(m.get("t"))))
            self.items[m["id"]] = {"meta": meta, "mine": mine, "t": m.get("t"), "status": ""}
            self._scroll_end()

        # ----- ไฟล์ / รูป / วีดีโอ -----
        def add_file(self, m):
            mine = m.get("mine")
            row = self._row(m.get("t"))
            col = box(row, bg="bg")
            col.pack(side="right" if mine else "left")
            holder = box(col, bg="bg")
            holder.pack(anchor="e" if mine else "w")
            it = {"m": m, "mine": mine, "holder": holder, "path": m.get("path"), "t": m.get("t"), "status": "",
                  "done": 0}
            it["meta"] = self._meta(col, mine, self._stamp(m.get("t")) if mine else
                                    "%s · %s" % (m.get("name_from") or self.peer, self._stamp(m.get("t"))))
            self.items[m["id"]] = it
            if mine and m.get("kind") in ("image", "video") and self._thumb(it, m["path"]):
                it["meta"].configure(text=self._stamp(m.get("t")) + " · " + tr("กำลังส่ง…"))
            else:
                self._file_card(it)
            self._scroll_end()

        def _file_card(self, it):
            m, mine = it["m"], it["mine"]
            for w in it["holder"].winfo_children():
                w.destroy()
            W, H = min(250, self.width - 90), 62
            c = tk.Canvas(it["holder"], width=W, height=H, highlightthickness=0, bd=0, bg=T.c("bg"))
            c.pack()
            c.create_image(0, 0, anchor="nw", image=shape_img(W, H, 14, T.c("sel") if mine else T.c("card"),
                                                              None if mine else T.c("border"), 1))
            ext = os.path.splitext(m.get("name", ""))[1].lstrip(".").lower()
            kind = m.get("kind")
            tb, tf = EXT_COLOR.get(ext, ("#ECE7FF", "#5B3AE6"))
            c.create_image(11, 11, anchor="nw", image=shape_img(40, 40, 10, tb))
            if kind in ("image", "video"):
                c.create_image(31, 31, image=icon("image" if kind == "image" else "video", 18, tf))
            else:
                c.create_text(31, 31, text=(ext[:4] or "FILE").upper(), fill=tf, font=T.f["smallbold"])
            name = m.get("name", "")
            f = T.f["smallbold"]
            maxw = W - 112
            while f.measure(name) > maxw and len(name) > 6:
                name = name[:len(name) // 2 - 2] + "…" + name[len(name) // 2 + 1:]
            c.create_text(61, 22, text=name, anchor="w", font=f, fill=T.c("text"))
            it["size_id"] = c.create_text(61, 40, text=fmt_size(m.get("size", 0)), anchor="w", font=T.f["small"],
                                          fill=T.c("muted"))
            it["bar_bg"] = c.create_rectangle(61, 52, W - 52, 55, fill=T.c("border"), outline="")
            it["bar"] = c.create_rectangle(61, 52, 61, 55, fill=T.c("accent"), outline="")
            it["card"], it["W"] = c, W
            self._card_action(it)

        def _card_action(self, it):
            c, W = it["card"], it["W"]
            if it.get("btn"):
                it["btn"].destroy()
            st = it["status"]
            if st in ("sent", "received") and it.get("path") and os.path.exists(it["path"]):
                b = RoundButton(c, "download" if not it["mine"] else "folder", kind="soft", w=32, h=32, icon_px=16,
                                bg=T.c("sel") if it["mine"] else T.c("card"),
                                command=lambda p=it["path"]: open_path(p) if not it["mine"] else show_in_folder(p))
                for k in ("bar", "bar_bg"):
                    c.delete(it[k])
            elif st in ("", "sending", "receiving"):
                b = RoundButton(c, "x", kind="soft", w=28, h=28, icon_px=13,
                                bg=T.c("sel") if it["mine"] else T.c("card"),
                                command=lambda: self.chat.cancel(it["m"]["id"]))
            else:
                b = None
                for k in ("bar", "bar_bg"):
                    c.delete(it[k])
            if b:
                c.create_window(W - 12, 31, window=b.cv, anchor="e")
            it["btn"] = b

        def _thumb(self, it, path):
            try:
                if it["m"].get("kind") == "image":
                    im = Image.open(path)
                    im.load()
                else:
                    import cv2
                    cap = cv2.VideoCapture(path)
                    ok, fr = cap.read()
                    cap.release()
                    if not ok:
                        return False
                    im = Image.fromarray(fr[:, :, ::-1])
                im = im.convert("RGB")
                im.thumbnail((min(230, self.width - 100), 180))
                if it["m"].get("kind") == "video":
                    d = _IDraw.Draw(im)
                    cx, cy, r = im.width // 2, im.height // 2, 20
                    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(18, 20, 28))
                    d.polygon([(cx - 6, cy - 10), (cx - 6, cy + 10), (cx + 11, cy)], fill=(255, 255, 255))
                ph = rounded_photo(im, 14)
                self.imgs.append(ph)
                for w in it["holder"].winfo_children():
                    w.destroy()
                t = T.track(tk.Label(it["holder"], image=ph, cursor="hand2", bd=0), bg="bg")
                t.pack()
                t.bind("<Button-1>", lambda e, p=path: open_path(p))
                it["thumb"] = True
                return True
            except Exception:
                return False

        def progress(self, ev):
            it = self.items.get(ev.get("id"))
            if not it or "m" not in it:
                return
            m = it["m"]
            size = ev.get("size") or m.get("size") or 1
            if "done" in ev:
                it["done"] = ev["done"]
            st = ev.get("status")
            if st:
                it["status"] = st
            if ev.get("path"):
                it["path"] = ev["path"]
            if it.get("thumb"):
                if st == "sent":
                    it["meta"].configure(text=self._stamp(it["t"]) + " · " + tr("ส่งแล้ว"))
                elif st == "failed":
                    it["meta"].configure(text="✗ " + (ev.get("text") or tr("ส่งไม่สำเร็จ")), fg=T.c("danger"))
                elif "done" in ev:
                    it["meta"].configure(text=self._stamp(it["t"]) + " · " + tr("กำลังส่ง… %d%%") % (100 * it["done"] / size))
                return
            c = it.get("card")
            if c is None:
                return
            try:
                if st in ("sent", "received"):
                    c.itemconfigure(it["size_id"], text=fmt_size(m.get("size", 0)) + "  ·  " +
                                    (tr("ส่งแล้ว") if st == "sent" else tr("ได้รับแล้ว")))
                    if st == "received" and m.get("kind") in ("image", "video") and self._thumb(it, it["path"]):
                        self._scroll_end()
                        return
                    self._card_action(it)
                elif st == "failed":
                    c.itemconfigure(it["size_id"], text="✗ " + (ev.get("text") or tr("ส่งไม่สำเร็จ")), fill=T.c("danger"))
                    self._card_action(it)
                elif "done" in ev:
                    W = it["W"]
                    c.coords(it["bar"], 61, 52, 61 + (W - 113) * min(1.0, it["done"] / size), 55)
                    c.itemconfigure(it["size_id"], text="%s / %s" % (fmt_size(it["done"]), fmt_size(size)))
            except tk.TclError:
                pass

        def note(self, text, color="muted"):
            row = self._row()
            lbl(row, text, fg=color, bg="bg", font="small", justify="center", anchor="center",
                wraplength=self.width - 50).pack(fill="x")
            self._scroll_end()

        # ----- กำลังพิมพ์ / อ่านแล้ว -----
        def _draw_typing(self):
            c = self.typing_cv
            try:
                c.delete("all")
            except tk.TclError:
                return
            c.configure(bg=T.c("bg"))
            c.create_image(0, 0, anchor="nw", image=shape_img(58, 34, 16, T.c("card"), T.c("border"), 1))
            for i in range(3):
                c.create_image(16 + i * 11, 14, anchor="nw", image=shape_img(6, 6, 3, T.c("muted")))

        def _show_typing(self):
            self.typing_until = time.time() + 4
            if not self.typing_row.winfo_ismapped():
                self.typing_row.pack(fill="x")
                self._scroll_end()

        def _mark_read(self, ids):
            for i in ids:
                it = self.items.get(i)
                if it and it["mine"] and "meta" in it and not it.get("thumb") and "m" not in it:
                    it["meta"].configure(text=self._stamp(it["t"]) + " · " + tr("อ่านแล้ว"))

        # ----- เหตุการณ์จาก engine -----
        def on_event(self, ev, visible=True):
            self.visible = visible
            k = ev.get("ev")
            if k in ("msg", "file"):
                if self.typing_row.winfo_ismapped() and not ev.get("mine"):
                    self.typing_row.pack_forget()
                (self.add_msg if k == "msg" else self.add_file)(ev)
                if not ev.get("mine"):
                    if visible:
                        self.chat.send_read([ev["id"]])
                    else:
                        self.unread_ids.append(ev["id"])
                        self.unread += 1
                        if self.on_unread:
                            self.on_unread(self.unread, ev)
            elif k == "progress":
                self.progress(ev)
            elif k == "typing":
                self._show_typing()
            elif k == "read":
                self._mark_read(ev.get("ids") or [])
            elif k == "error":
                self.note("✗ " + ev.get("text", ""), "danger")
            elif k in ("call_state", "call_incoming", "remote_video", "self_video", "call_error"):
                self.on_call(ev)

        def seen(self):
            self.visible = True
            if self.unread_ids:
                self.chat.send_read(self.unread_ids)
            self.unread_ids, self.unread = [], 0
            if self.on_unread:
                self.on_unread(0, None)

        # ================= โทร =================
        def _build_call(self):
            cb = self.callbox
            self.c_head = tk.Frame(cb, bd=0, bg=self.CALL_BG)
            self.c_head.pack(fill="x", padx=12, pady=(12, 10))
            self.c_title = tk.Label(self.c_head, text=self.peer, font=T.f["bold"], fg="#FFFFFF", bg=self.CALL_BG)
            self.c_title.pack(anchor="w")
            self.c_sub = tk.Label(self.c_head, text="", font=T.f["small"], fg="#A9B0C2", bg=self.CALL_BG)
            self.c_sub.pack(anchor="w")
            self.stage = tk.Canvas(cb, highlightthickness=0, bd=0, bg=self.CALL_BG, height=10)
            self.stage.pack(fill="x", padx=12)
            self.c_ctrl = tk.Frame(cb, bd=0, bg=self.CALL_BG)
            self.c_ctrl.pack(pady=(12, 14))
            B = self.CALL_BG
            self.mic_btn = RoundButton(self.c_ctrl, "mic", kind="dark", w=46, h=46, icon_px=20, bg=B,
                                       command=self._toggle_mute)
            self.cam_btn = RoundButton(self.c_ctrl, "video", kind="dark", w=46, h=46, icon_px=20, bg=B,
                                       command=self._toggle_cam)
            self.spk_btn = RoundButton(self.c_ctrl, "speaker", kind="dark", w=46, h=46, icon_px=20, bg=B,
                                       command=self._toggle_spk)
            self.hang_btn = RoundButton(self.c_ctrl, "hangup", kind="danger", w=64, h=46, icon_px=22, bg=B,
                                        command=self._hang)
            self.decline_btn = RoundButton(self.c_ctrl, "hangup", text=tr("ปฏิเสธ"), kind="danger",
                                           w=int((self.width - 60) / 2), h=44, bg=B, font="bold",
                                           command=lambda: self.call.decline())
            self.accept_btn = RoundButton(self.c_ctrl, "video", text=tr("รับสาย"), kind="success",
                                          w=int((self.width - 60) / 2), h=44, bg=B, font="bold",
                                          command=self._answer)
            self.audio_only = tk.Label(cb, text=tr("รับด้วยเสียงอย่างเดียว"), font=T.f["small"], fg="#C9CFDD", bg=B,
                                       cursor="hand2")
            self.audio_only.bind("<Button-1>", lambda e: self.call.accept(video=False))

        def _ctrl_layout(self, which):
            for b in (self.mic_btn, self.cam_btn, self.spk_btn, self.hang_btn, self.decline_btn, self.accept_btn):
                b.pack_forget()
            for b in which:
                b.pack(side="left", padx=5)

        def _stage_avatar(self, text):
            c = self.stage
            w = self.width - 24
            c.configure(height=150)
            c.delete("all")
            ph, ch, fg = avatar_img(self.peer, 64, dot=False, ring=16)
            c.create_image(w / 2, 62, image=ph)
            c.create_text(w / 2, 62, text=ch, fill=fg, font=(T.f["bold"].actual("family"), 24, "bold"))
            c.create_text(w / 2, 128, text=text, fill="#C9CFDD", font=T.f["base"])

        def _stage_video(self):
            c = self.stage
            w = self.width - 24
            h = int(w * 0.75)
            c.configure(height=h)
            c.delete("all")
            if self.remote_photo is not None:
                c.create_image(0, 0, anchor="nw", image=self.remote_photo)
            else:
                c.create_image(0, 0, anchor="nw", image=shape_img(w, h, 14, "#2B3245"))
                ph, ch, fg = avatar_img(self.peer, 64, dot=False)
                c.create_image(w / 2, h / 2, image=ph)
                c.create_text(w / 2, h / 2, text=ch, fill=fg, font=(T.f["bold"].actual("family"), 24, "bold"))
            if self.self_photo is not None:
                c.create_image(w - 8, 8, anchor="ne", image=self.self_photo)

        def _call(self, video):
            if self.call.state != "idle" or not self.chat_ok:
                return
            a, v = media_available()
            if not a:
                self.note("✗ " + tr("ไม่พบไมโครโฟนหรือลำโพงในเครื่องนี้ จึงโทรไม่ได้"), "danger")
                return
            if video and not v:
                self.note(tr("ไม่พบกล้องในเครื่องนี้ — จะโทรด้วยเสียงอย่างเดียว"))
            self.call.start_call(video)

        def _answer(self):
            self.call.accept(video=self.call.peer_video and media_available()[1])

        def _hang(self):
            if self.call.state == "ringing":
                self.call.decline()
            else:
                self.call.hangup()

        def _toggle_mute(self):
            self.call.set_mute(not self.call.muted)
            self.mic_btn.configure(icon="mic-off" if self.call.muted else "mic",
                                   kind="danger_soft" if self.call.muted else "dark")

        def _toggle_cam(self):
            self.call.set_video(not self.call.video)
            self.cam_btn.configure(icon="video" if self.call.video else "video-off",
                                   kind="dark" if self.call.video else "danger_soft")
            if not self.call.video:
                self.self_photo = None
                self._stage_video() if self.call.peer_video or self.remote_photo else None

        def _toggle_spk(self):
            self.call.speaker_off = not getattr(self.call, "speaker_off", False)
            self.spk_btn.configure(icon="speaker-off" if self.call.speaker_off else "speaker",
                                   kind="danger_soft" if self.call.speaker_off else "dark")

        def _video_photo(self, jpg, w, h, r):
            im = Image.open(io.BytesIO(jpg))
            im.load()
            im = im.convert("RGB")
            iw, ih = im.size
            sc = max(w / iw, h / ih)
            im = im.resize((max(1, int(iw * sc)), max(1, int(ih * sc))), Image.BILINEAR)
            x0, y0 = (im.width - w) // 2, (im.height - h) // 2
            return rounded_photo(im.crop((x0, y0, x0 + w, y0 + h)), r)

        def on_call(self, ev):
            k = ev.get("ev")
            st = self.call.state
            if k == "call_error":
                self.note("✗ " + ev.get("text", ""), "danger")
                return
            if k == "remote_video":
                if st != "active":
                    return
                w = self.width - 24
                if ev.get("jpg") is None:
                    self.remote_photo = None
                else:
                    try:
                        self.remote_photo = self._video_photo(ev["jpg"], w, int(w * 0.75), 14)
                    except Exception:
                        return
                self._stage_video()
                return
            if k == "self_video":
                if ev.get("jpg") is None:
                    self.self_photo = None
                else:
                    try:
                        self.self_photo = self._video_photo(ev["jpg"], 84, 112, 10)
                    except Exception:
                        return
                if st == "active" and (self.call.peer_video or self.remote_photo is not None or self.call.video):
                    self._stage_video()
                return
            if k == "call_incoming":
                self.callbox.pack(fill="x", padx=12, pady=(0, 12), after=self._anchor())
                video = ev.get("video")
                self.c_title.configure(text=self.peer)
                self.c_sub.configure(text=tr("วีดีโอคอลเข้า…") if video else tr("สายเรียกเข้า…"))
                self._stage_avatar(tr("วีดีโอคอลเข้า…") if video else tr("สายเรียกเข้า…"))
                self.accept_btn.configure(icon="video" if video else "phone")
                self._ctrl_layout([self.decline_btn, self.accept_btn])
                if video and media_available()[1]:
                    self.audio_only.pack(pady=(0, 12))
                if self.on_unread:
                    self.on_unread(-1, ev)
                try:
                    self.frame.winfo_toplevel().bell()
                except tk.TclError:
                    pass
                return
            # call_state
            self.audio_only.pack_forget()
            if st == "idle":
                self.callbox.pack_forget()
                self.remote_photo = self.self_photo = None
                self.mic_btn.configure(icon="mic", kind="dark")
                self.cam_btn.configure(icon="video", kind="dark")
                reason = ev.get("reason")
                if ev.get("was") == "active":
                    d = int(ev.get("duration", 0))
                    self.note(tr("วางสายแล้ว · %d:%02d") % (d // 60, d % 60))
                elif reason in ("declined", "busy", "nodev"):
                    self.note({"declined": tr("อีกฝั่งไม่รับสาย"), "busy": tr("อีกฝั่งสายไม่ว่าง"),
                               "nodev": tr("อีกฝั่งไม่มีไมโครโฟน/ลำโพง")}[reason])
                elif ev.get("was") in ("ringing", "calling"):
                    self.note(tr("ยกเลิกการโทร"))
                return
            self.callbox.pack(fill="x", padx=12, pady=(0, 12), after=self._anchor())
            if st == "calling":
                self.c_sub.configure(text=tr("กำลังโทรหา %s …") % self.peer)
                self._stage_avatar(tr("กำลังโทร…"))
                self._ctrl_layout([self.hang_btn])
            elif st == "active":
                ctrls = [self.mic_btn]
                if media_available()[1]:
                    ctrls.append(self.cam_btn)
                    self.cam_btn.configure(icon="video" if self.call.video else "video-off",
                                           kind="dark" if self.call.video else "danger_soft")
                self._ctrl_layout(ctrls + [self.spk_btn, self.hang_btn])
                if self.call.peer_video or self.call.video:
                    self._stage_video()
                else:
                    self._stage_avatar(tr("กำลังคุย"))

        def _anchor(self):
            """วางพื้นที่โทรไว้ใต้ส่วนหัว/ปุ่มควบคุม"""
            kids = [w for w in self.body.winfo_children() if w is not self.callbox]
            return kids[1] if self.mode == "controller" and self.viewer is not None else kids[0]

        def _tick(self):
            try:
                if self.call.state == "active" and self.call.started:
                    d = int(time.time() - self.call.started)
                    self.c_sub.configure(text="%s · %d:%02d%s" % (
                        tr("วีดีโอคอล") if (self.call.video or self.call.peer_video) else tr("โทรเสียง"),
                        d // 60, d % 60, "  ·  " + tr("ปิดไมค์") if self.call.muted else ""))
                if self.typing_row.winfo_ismapped() and time.time() > self.typing_until:
                    self.typing_row.pack_forget()
                self.frame.after(500, self._tick)
            except tk.TclError:
                pass


    # ------------------------------------------------------------------
    FILE_KINDS = {
        "pdf": ("pdf",), "img": ("jpg", "jpeg", "png", "gif", "bmp", "heic", "webp", "svg", "tif", "tiff", "ico", "icns"),
        "audio": ("mp3", "wav", "aac", "m4a", "flac", "ogg", "aiff"),
        "video": ("mp4", "mov", "avi", "mkv", "wmv", "m4v", "webm"),
        "zip": ("zip", "rar", "7z", "tar", "gz", "bz2", "xz", "dmg", "iso", "tgz"),
        "doc": ("doc", "docx", "rtf", "odt", "pages"), "sheet": ("xls", "xlsx", "csv", "ods", "numbers"),
        "slide": ("ppt", "pptx", "key", "odp"),
        "code": ("py", "js", "ts", "html", "htm", "css", "json", "xml", "sh", "c", "cpp", "h", "java", "go", "rs",
                 "php", "yml", "yaml", "sql", "swift", "kt"),
        "app": ("exe", "msi", "app", "pkg", "bat", "command", "apk"),
        "text": ("txt", "md", "log", "ini", "cfg", "conf", "env"),
        "cad": ("dwg", "dxf", "stl", "step", "stp", "obj", "3mf"),
    }
    KIND_OF = {ext: k for k, exts in FILE_KINDS.items() for ext in exts}
    KIND_COLOR = {"pdf": "#E5372B", "img": "#2EAD5B", "audio": "#9B51E0", "video": "#E0457B", "zip": "#F08C1B",
                  "doc": "#2F6FDE", "sheet": "#1E8E3E", "slide": "#E8590C", "code": "#5865F2", "app": "#374151",
                  "text": "#8A94A6", "cad": "#0EA5A4", "file": "#B5BCC9"}
    _icon_cache = {}

    def file_icon(kind):
        """ไอคอนชนิดไฟล์ 16px (วาดด้วย Pillow)"""
        if kind in _icon_cache:
            return _icon_cache[kind]
        from PIL import ImageDraw
        S = 4
        im = Image.new("RGBA", (16 * S, 16 * S), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        if kind == "folder":
            d.rounded_rectangle([1 * S, 3 * S, 7 * S, 6 * S], radius=S, fill="#3D8EF0")
            d.rounded_rectangle([1 * S, 4.5 * S, 15 * S, 14 * S], radius=1.4 * S, fill="#5AA9FF")
            d.rectangle([1 * S, 6 * S, 15 * S, 7 * S], fill="#7BBBFF")
        elif kind == "up":
            d.rounded_rectangle([1 * S, 3 * S, 7 * S, 6 * S], radius=S, fill="#8FB8E8")
            d.rounded_rectangle([1 * S, 4.5 * S, 15 * S, 14 * S], radius=1.4 * S, fill="#A9CBF2")
        else:
            col = KIND_COLOR.get(kind, KIND_COLOR["file"])
            d.polygon([(3 * S, 1 * S), (10 * S, 1 * S), (13 * S, 4 * S), (13 * S, 15 * S), (3 * S, 15 * S)],
                      fill="#FFFFFF", outline="#C3C8D2")
            d.polygon([(10 * S, 1 * S), (10 * S, 4 * S), (13 * S, 4 * S)], fill="#DDE1E8")
            d.rectangle([3 * S, 9 * S, 13 * S, 13 * S], fill=col)
        img = ImageTk.PhotoImage(im.resize((16, 16), resample=1))
        _icon_cache[kind] = img
        return img

    def kind_of(name, isdir):
        if isdir:
            return "folder"
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        return KIND_OF.get(ext, "file")

    def fmt_be(ts):
        if not ts:
            return ""
        t = datetime.fromtimestamp(ts)
        return "%d/%d/%d %02d:%02d" % (t.day, t.month, t.year + 543, t.hour, t.minute)

    class FilePane:
        """รายการไฟล์ 1 ฝั่ง — side = "local" (เครื่องนี้) หรือ "remote" (เครื่องปลายทาง)"""

        def __init__(self, fw, parent, side, title, subtitle):
            self.fw, self.side = fw, side
            self.cur, self.parent_path, self.pending = None, None, None
            self.back, self.hist = [], []
            self.data, self.entries = [], {}
            self.sort_col, self.sort_rev = "name", False
            right = side == "remote"
            self.frame = f = box(parent, bg="bg")

            hdr = box(f, bg="bg")
            hdr.pack(fill="x", padx=12, pady=(12, 2))
            av = T.track(tk.Canvas(hdr, width=40, height=40, highlightthickness=0), bg="bg")
            av.pack(side="right" if right else "left")

            def draw_av():
                av.delete("all")
                av.create_oval(2, 2, 38, 38, fill=T.c("subtle"), outline=T.c("border"))
                av.create_oval(14, 9, 26, 21, outline=T.c("muted"), width=2)
                av.create_arc(9, 22, 31, 42, start=0, extent=180, style="arc", outline=T.c("muted"), width=2)
            draw_av()
            T.on_change(draw_av)
            tx = box(hdr, bg="bg")
            tx.pack(side="right" if right else "left", padx=10)
            lbl(tx, title, fg="ok", bg="bg", font="bold", anchor="e" if right else "w").pack(fill="x")
            lbl(tx, subtitle, fg="muted", bg="bg", font="small", anchor="e" if right else "w").pack(fill="x")

            act = box(f, bg="bg")
            act.pack(fill="x", padx=12, pady=(0, 6))
            side_ = "left" if right else "right"
            main = ("⬇  Download" if right else "⬆  Upload")
            ttk.Button(act, text=main, style="Tool.Accent.TButton",
                       command=self.fw.download if right else self.fw.upload).pack(side=side_)
            ttk.Button(act, text=tr("+ โฟลเดอร์ใหม่"), style="Tool.TButton", command=self.mkdir).pack(side=side_, padx=4)
            ttk.Button(act, text=tr("✕ ลบ"), style="Tool.TButton", command=self.delete).pack(side=side_)

            nav = box(f, bg="bg")
            nav.pack(fill="x", padx=12, pady=(0, 6))
            for txt, cmd in (("←", self.go_back), ("↑", self.go_up), ("⌂", self.go_home), ("⟳", self.refresh)):
                ttk.Button(nav, text=txt, width=3, style="Tool.TButton", command=cmd).pack(side="left", padx=(0, 3))
            self.path_var = tk.StringVar()
            self.path_cb = ttk.Combobox(nav, textvariable=self.path_var)
            self.path_cb.pack(side="left", fill="x", expand=True, padx=(4, 0))
            self.path_cb.bind("<Return>", lambda e: self.go(self.path_var.get().strip() or None))
            self.path_cb.bind("<<ComboboxSelected>>", lambda e: self.go(self.path_var.get().strip() or None))

            tf = box(f, bg="card")
            tf.pack(fill="both", expand=True, padx=12, pady=(0, 8))
            t = self.tree = ttk.Treeview(tf, columns=("mtime", "size"), show="tree headings", selectmode="extended")
            t.heading("#0", text="Name", anchor="w", command=lambda: self.sort_by("name"))
            t.heading("mtime", text="Modified", anchor="w", command=lambda: self.sort_by("mtime"))
            t.heading("size", text="Size", anchor="e", command=lambda: self.sort_by("size"))
            t.column("#0", width=260, stretch=True)
            t.column("mtime", width=130, stretch=False)
            t.column("size", width=80, stretch=False, anchor="e")
            sb = ttk.Scrollbar(tf, orient="vertical", command=t.yview)
            t.configure(yscrollcommand=sb.set)
            t.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            t.bind("<Double-1>", self.on_open)
            t.bind("<Return>", self.on_open)
            t.bind("<BackSpace>", lambda e: self.go_up())
            t.bind("<Delete>", lambda e: self.delete())
            t.bind("<ButtonPress-1>", self._drag_start, add="+")
            t.bind("<B1-Motion>", self._drag_motion, add="+")
            t.bind("<ButtonRelease-1>", self._drag_end, add="+")
            self.status = lbl(f, "", fg="muted", bg="bg", font="small")
            self.status.pack(fill="x", padx=14, pady=(0, 4))
            self._drag = None

        # ----- navigation -----
        def go(self, path, record=True):
            if record and self.cur is not None and path != self.cur:
                self.back.append(self.cur)
            if self.side == "local":
                try:
                    d = list_dir(path)
                except Exception as e:
                    messagebox.showerror(APP, tr("เปิดโฟลเดอร์ไม่ได้: %s") % err_text(e), parent=self.fw.win)
                    return
                self.populate(d)
            else:
                self.pending = self.fw.fc.list(path)
                self.status.configure(text=tr("กำลังโหลด…"))

        def go_back(self):
            if self.back:
                self.go(self.back.pop(), record=False)

        def go_up(self):
            if self.parent_path is not None:
                self.go(self.parent_path)

        def go_home(self):
            self.go(None)

        def refresh(self):
            self.go(self.cur, record=False)

        def populate(self, d):
            self.cur, self.parent_path = d.get("path"), d.get("parent")
            self.data = d.get("entries", [])
            shown = self.cur or (tr("(ไดรฟ์ทั้งหมด)") if self.side == "remote" else "")
            self.path_var.set(shown)
            if self.cur and self.cur not in self.hist:
                self.hist.insert(0, self.cur)
                del self.hist[20:]
            extra = []
            if self.side == "local":
                home = os.path.expanduser("~")
                extra = [home] + [os.path.join(home, x) for x in ("Desktop", "Documents", "Downloads")
                                  if os.path.isdir(os.path.join(home, x))]
            self.path_cb.configure(values=list(dict.fromkeys(self.hist + extra)))
            self.render()

        def sort_by(self, col):
            self.sort_rev = (not self.sort_rev) if self.sort_col == col else False
            self.sort_col = col
            self.render()

        def render(self):
            t = self.tree
            t.delete(*t.get_children(""))
            self.entries.clear()
            if self.parent_path is not None:
                t.insert("", "end", iid="up", text="  ..", image=file_icon("up"), values=("", "--"))
            key = {"name": lambda e: e["n"].lower(), "mtime": lambda e: e.get("m", 0),
                   "size": lambda e: e.get("s", 0)}[self.sort_col]
            dirs = sorted([e for e in self.data if e["d"]], key=key, reverse=self.sort_rev)
            files = sorted([e for e in self.data if not e["d"]], key=key, reverse=self.sort_rev)
            for i, e in enumerate(dirs + files):
                iid = "e%d" % i
                self.entries[iid] = e
                t.insert("", "end", iid=iid, text="  " + e["n"], image=file_icon(kind_of(e["n"], e["d"])),
                         values=(fmt_be(e.get("m")), "--" if e["d"] else fmt_size(e["s"])))
            for c, name in (("#0", "name"), ("mtime", "mtime"), ("size", "size")):
                base = {"name": "Name", "mtime": "Modified", "size": "Size"}[name]
                arrow = (" ▼" if self.sort_rev else " ▲") if self.sort_col == name else ""
                t.heading(c, text=base + arrow)
            nd, nf = len(dirs), len(files)
            self.status.configure(text=tr("%d โฟลเดอร์ · %d ไฟล์") % (nd, nf))

        def selected_paths(self):
            return [self.entries[i]["p"] for i in self.tree.selection() if i in self.entries]

        def on_open(self, e=None):
            sel = self.tree.selection()
            if not sel:
                return
            if sel[0] == "up":
                self.go_up()
                return
            ent = self.entries.get(sel[0])
            if ent and ent["d"]:
                self.go(ent["p"])
            elif ent:
                (self.fw.download if self.side == "remote" else self.fw.upload)()

        # ----- actions -----
        def mkdir(self):
            if not self.cur:
                return
            name = simpledialog.askstring(APP, tr("ชื่อโฟลเดอร์ใหม่:"), parent=self.fw.win)
            if not name or not name.strip():
                return
            if self.side == "local":
                try:
                    parts = safe_parts(name.strip())
                    os.mkdir(os.path.join(self.cur, parts[0]))
                except Exception as e:
                    messagebox.showerror(APP, tr("สร้างโฟลเดอร์ไม่ได้: %s") % err_text(e), parent=self.fw.win)
                self.refresh()
            else:
                self.pending = self.fw.fc.mkdir(self.cur, name.strip())

        def delete(self):
            paths = self.selected_paths()
            if not paths:
                return
            where = tr("เครื่องนี้") if self.side == "local" else tr("เครื่องปลายทาง")
            names = "\n".join("• " + os.path.basename(p.rstrip("\\/")) for p in paths[:8])
            more = tr("\n… และอีก %d รายการ") % (len(paths) - 8) if len(paths) > 8 else ""
            trash = tr(" (ย้ายไปถังขยะ)") if (self.side == "local" and SYSTEM == "Darwin") else ""
            if not messagebox.askyesno(APP, tr("ลบ %d รายการบน%s%s?\n\n%s%s") % (len(paths), where, trash, names, more),
                                       icon="warning", default="no", parent=self.fw.win):
                return
            if self.side == "local":
                errs = []
                for p in paths:
                    try:
                        delete_path(p)
                    except Exception as e:
                        errs.append("%s: %s" % (os.path.basename(p), err_text(e)))
                if errs:
                    messagebox.showerror(APP, tr("ลบไม่สำเร็จบางรายการ:\n") + "\n".join(errs[:10]), parent=self.fw.win)
                self.refresh()
            else:
                self.pending = self.fw.fc._fs("delete", path=self.cur, paths=paths)

        # ----- drag & drop ไปอีกฝั่ง -----
        def _drag_start(self, e):
            row = self.tree.identify_row(e.y)
            self._drag = {"x": e.x_root, "y": e.y_root, "on": False} if row and row != "up" else None

        def _drag_motion(self, e):
            if self._drag and not self._drag["on"] and (abs(e.x_root - self._drag["x"]) + abs(e.y_root - self._drag["y"])) > 12:
                self._drag["on"] = True
                self.tree.configure(cursor="hand2")

        def _drag_end(self, e):
            d, self._drag = self._drag, None
            self.tree.configure(cursor="")
            if not d or not d["on"]:
                return
            target = self.fw.win.winfo_containing(e.x_root, e.y_root)
            other = self.fw.remote if self.side == "local" else self.fw.local
            w = target
            while w is not None:
                if w is other.tree or w is other.frame:
                    (self.fw.upload if self.side == "local" else self.fw.download)()
                    return
                w = w.master

    class FileWindow:
        """หน้าต่างรับ-ส่งไฟล์ 2 ฝั่ง: ซ้าย = เครื่องนี้, ขวา = เครื่องปลายทาง"""

        def __init__(self, viewer):
            self.v, self.fc, self.app = viewer, viewer.files, viewer.app
            self.speed = {}
            w = self.win = T.track(tk.Toplevel(viewer.win), bg="bg")
            w.title(tr("รับ-ส่งไฟล์ — %s") % viewer.info.get("name", viewer.host))
            w.geometry("1120x780")
            w.minsize(820, 560)
            w.protocol("WM_DELETE_WINDOW", w.withdraw)
            set_app_icon(w)

            pw = tk.PanedWindow(w, orient="horizontal", sashwidth=6, bd=0)
            T.track(pw, bg="border")
            pw.pack(fill="both", expand=True)
            my_id = fmt_id(self.app.cfg.get("host_id", ""))
            rid = viewer.host.replace("ID ", "")
            self.local = FilePane(self, pw, "local", "%s (%s)" % (computer_name(), my_id), tr("เครื่องนี้ · This device"))
            self.remote = FilePane(self, pw, "remote", "%s (%s)" % (viewer.info.get("name", ""), rid),
                                   tr("เครื่องปลายทาง · Remote device"))
            pw.add(self.local.frame, stretch="always", minsize=380)
            pw.add(self.remote.frame, stretch="always", minsize=380)

            T.track(tk.Frame(w, height=1, bd=0), bg="border").pack(fill="x")
            bottom = box(w, bg="bg")
            bottom.pack(fill="x")
            head = box(bottom, bg="bg")
            head.pack(fill="x", padx=12, pady=(8, 4))
            lbl(head, tr("การรับ-ส่งไฟล์"), fg="text", bg="bg", font="bold").pack(side="left")
            ttk.Button(head, text=tr("ล้างรายการที่เสร็จแล้ว"), style="Tool.TButton", command=self.clear_done).pack(side="right")
            ttk.Button(head, text=tr("ยกเลิกที่เลือก"), style="Tool.TButton", command=self.cancel_sel).pack(side="right", padx=6)
            self.msg = lbl(head, tr("ลากไฟล์ข้ามฝั่งเพื่อส่งได้"), fg="muted", bg="bg", font="small")
            self.msg.pack(side="right", padx=12)
            tf = box(bottom, bg="card")
            tf.pack(fill="x", padx=12, pady=(0, 12))
            x = self.xfer = ttk.Treeview(tf, columns=("dir", "name", "size", "prog", "speed", "status"),
                                         show="headings", height=5)
            for c, txt, wd, st in (("dir", "", 115, False), ("name", tr("ไฟล์"), 240, True), ("size", tr("ขนาด"), 85, False),
                                   ("prog", tr("ความคืบหน้า"), 175, False), ("speed", tr("ความเร็ว"), 90, False),
                                   ("status", tr("สถานะ"), 280, True)):
                x.heading(c, text=txt)
                x.column(c, width=wd, stretch=st, anchor="e" if c in ("size", "speed") else "w")
            x.tag_configure("done", foreground=T.c("ok"))
            x.tag_configure("error", foreground=T.c("danger"))
            x.tag_configure("cancelled", foreground=T.c("muted"))
            x.pack(fill="x")

            self.local.go(self.app.cfg.get("download_dir") or os.path.join(os.path.expanduser("~"), "Downloads"))
            if self.local.cur is None:
                self.local.go(None)
            self.remote.go(None)
            self.win.after(150, self._poll)

        def show(self):
            self.win.deiconify()
            self.win.lift()

        def upload(self):
            paths = self.local.selected_paths()
            if not paths:
                messagebox.showinfo(APP, tr("เลือกไฟล์หรือโฟลเดอร์ฝั่งซ้าย (เครื่องนี้) ที่จะส่งก่อน"), parent=self.win)
                return
            if not self.remote.cur:
                messagebox.showinfo(APP, tr("เปิดโฟลเดอร์ปลายทางฝั่งขวาก่อน"), parent=self.win)
                return
            self._add_job(self.fc.upload(paths, self.remote.cur))

        def download(self):
            paths = self.remote.selected_paths()
            if not paths:
                messagebox.showinfo(APP, tr("เลือกไฟล์หรือโฟลเดอร์ฝั่งขวา (เครื่องปลายทาง) ที่จะดาวน์โหลดก่อน"), parent=self.win)
                return
            if not self.local.cur:
                messagebox.showinfo(APP, tr("เปิดโฟลเดอร์ปลายทางฝั่งซ้ายก่อน"), parent=self.win)
                return
            self._add_job(self.fc.download(paths, self.local.cur))

        def cancel_sel(self):
            for iid in self.xfer.selection():
                self.fc.cancel(int(iid))

        def clear_done(self):
            for iid in self.xfer.get_children(""):
                job = self.fc.jobs.get(int(iid))
                if not job or job["state"] != "active":
                    self.xfer.delete(iid)
                    self.fc.jobs.pop(int(iid), None)

        def _add_job(self, job):
            self.xfer.insert("", 0, iid=str(job["tid"]), values=self._job_values(job))

        def _job_values(self, job):
            cur = self.fc.progress(job)
            total = job["total"]
            pct = (100.0 * cur / total) if total else (100.0 if job["state"] == "done" else 0.0)
            bar = "█" * int(pct / 10) + "░" * (10 - int(pct / 10))
            now = time.time()
            t_prev, b_prev, spd = self.speed.get(job["tid"], (job["t0"], 0, 0.0))
            if now - t_prev >= 0.5:
                spd = spd * 0.4 + 0.6 * (cur - b_prev) / (now - t_prev)
                self.speed[job["tid"]] = (now, cur, spd)
            if job["state"] != "active":
                spd = cur / max(0.001, (job["t1"] or now) - job["t0"])
            arrow = "⬆ Upload" if job["dir"] == "up" else "⬇ Download"
            return (arrow, job["name"], fmt_size(total) if total else "-", "%s %3.0f%%" % (bar, pct),
                    "%s/s" % fmt_size(spd) if cur else "", job["status"])

        def _poll(self):
            if self.v.closed:
                return
            try:
                while True:
                    kind, d = self.fc.events.get_nowait()
                    if kind == "fs" and d.get("id") == self.remote.pending:
                        if d.get("ok"):
                            self.remote.populate(d)
                        else:
                            self.remote.status.configure(text="✗ %s" % tr(d.get("err")))
                            messagebox.showerror(APP, tr(d.get("err")) or tr("ผิดพลาด"), parent=self.win)
                    elif kind == "job_done":
                        job = self.fc.jobs.get(d)
                        if job and job["state"] == "done":
                            if job["dir"] == "up" and job["dest"] == self.remote.cur:
                                self.remote.refresh()
                            if job["dir"] == "down" and job["dest"] == self.local.cur:
                                self.local.refresh()
                            self.msg.configure(text=tr("✓ %s เสร็จ: %s") % ("Upload" if job["dir"] == "up" else "Download",
                                                                       job["name"]))
            except queue.Empty:
                pass
            for iid in self.xfer.get_children(""):
                job = self.fc.jobs.get(int(iid))
                if job:
                    self.xfer.item(iid, values=self._job_values(job),
                                   tags=() if job["state"] == "active" else (job["state"],))
            self.win.after(200, self._poll)

    # ------------------------------------------------------------------
    class App:
        THEME_LABEL = {"auto": tr("◐  อัตโนมัติ"), "light": tr("☀  สว่าง"), "dark": tr("☾  มืด")}

        def __init__(self, root):
            self.root = root
            self.cfg = load_config()
            if not self.cfg.get("host_id") or not self.cfg.get("host_secret"):
                self.cfg.update({"host_id": new_host_id(), "host_secret": secrets.token_hex(24)})
                save_config(self.cfg)
            # ค่าจากไฟล์ .env มีผลเหนือค่าที่บันทึกในโปรแกรม
            for env_k, cfg_k in (("ASK_BEFORE_ACCEPT", "ask"), ("ALLOW_CONTROL", "allow_control"),
                                 ("ALLOW_FILES", "allow_files")):
                if ENV.get(env_k, "") != "":
                    self.cfg[cfg_k] = env_bool(env_k, self.cfg.get(cfg_k, True))
            if env_str("HOST_PASSWORD"):
                self.cfg["password"] = env_str("HOST_PASSWORD")
            if env_str("DOWNLOAD_DIR"):
                self.cfg["download_dir"] = os.path.expanduser(env_str("DOWNLOAD_DIR"))
            self.q = queue.Queue()
            self.server = None
            self.viewers = []
            self.banner_state = ("off", "")
            self.relay_state = {"mon": "checking", "data": None, "host": None, "host_text": "", "t": None}
            self.session_who = None
            root.title("%s — Remote Desktop" % APP)
            root.geometry("1000x780")
            root.minsize(900, 700)
            self._build_header(root)
            nb = self.nb = ttk.Notebook(root)
            nb.pack(fill="both", expand=True)
            t1, t2, t3 = (ttk.Frame(nb, padding=(16, 14, 16, 16)) for _ in range(3))
            nb.add(t1, text=tr("ควบคุมเครื่องอื่น"))
            nb.add(t2, text=tr("ให้เครื่องอื่นควบคุมเครื่องนี้"))
            nb.add(t3, text=tr("ตั้งค่า Server"))
            self._build_client(t1)
            self._build_server(t2)
            self._build_relay(t3)
            self._update_id_row()
            T.on_change(lambda: self._banner(*self.banner_state))   # noqa
            if self.cfg.get("last_tab") in (1, 2):
                nb.select(self.cfg["last_tab"])
            nb.bind("<<NotebookTabChanged>>", lambda e: self._tab(nb))
            root.after(50, self._poll)
            self.monitor = RelayMonitor(self._relay_conn, self.q)
            self.monitor.start()
            root.after(3000, self._update_loop)
            root.after(400, lambda: self.start_server(auto=True))   # พร้อมรับการเชื่อมต่ออัตโนมัติเสมอ

        def _tab(self, nb):
            self.cfg["last_tab"] = nb.index(nb.select())
            save_config(self.cfg)

        # ---------------- header ----------------
        def _build_header(self, root):
            hdr = T.track(tk.Frame(root, height=68), bg="header")
            hdr.pack(fill="x")
            hdr.pack_propagate(False)
            logo = T.track(tk.Canvas(hdr, width=42, height=42, highlightthickness=0), bg="header")
            logo.pack(side="left", padx=(18, 12))

            def draw_logo():
                logo.delete("all")
                r, x0, y0, x1, y1 = 10, 2, 2, 40, 40
                pts = [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1, x1 - r, y1, x0 + r, y1,
                       x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]
                logo.create_polygon(pts, smooth=True, fill="#FFFFFF", outline="")
                logo.create_rectangle(10, 11, 32, 26, fill=T.c("header"), outline="")
                logo.create_rectangle(19, 26, 23, 30, fill=T.c("header"), outline="")
                logo.create_rectangle(15, 30, 27, 32, fill=T.c("header"), outline="")
                logo.create_polygon(17, 14, 17, 23, 19.5, 21, 21.5, 25, 23, 24.3, 21, 20.5, 24.5, 20.5,
                                    fill="#FFFFFF", outline="")
            draw_logo()
            T.on_change(draw_logo)
            txt = box(hdr, bg="header")
            txt.pack(side="left")
            lbl(txt, "NetRemote", fg="hdr_fg", bg="header", font="h1").pack(anchor="w")
            lbl(txt, tr("Remote Desktop · v%s") % VERSION, fg="hdr_muted", bg="header",
                font="small").pack(anchor="w")
            self.theme_btn = lbl(hdr, self.THEME_LABEL[T.mode], fg="hdr_fg", bg="header2", font="smallbold",
                                 padx=14, pady=6, cursor="hand2")
            self.theme_btn.pack(side="right", padx=18)
            self.theme_btn.bind("<Button-1>", lambda e: self.cycle_theme())
            if not ENV.get("LANGUAGE", "").strip():
                self.lang_btn = lbl(hdr, "🌐  English" if LANG == "th" else "🌐  ไทย", fg="hdr_fg", bg="header2",
                                    font="smallbold", padx=14, pady=6, cursor="hand2")
                self.lang_btn.pack(side="right", padx=(10, 0))
                self.lang_btn.bind("<Button-1>", lambda e: self.switch_lang())
            self.relay_pill = tk.Label(hdr, text=tr("●  Server: กำลังตรวจสอบ…"), font=T.f["smallbold"], padx=14, pady=6,
                                       cursor="hand2", bg="#B45309", fg="#FFFFFF")
            self.relay_pill.pack(side="right")
            self.update_badge = tk.Label(hdr, text="", font=T.f["smallbold"], padx=12, pady=6, cursor="hand2",
                                         bg="#F59E0B", fg="#1F1300")
            self.update_badge.bind("<Button-1>", lambda e: self.install_update() if self.update_ready
                                   else self.nb.select(2))
            self.relay_pill.bind("<Button-1>", lambda e: self.nb.select(2))

        def switch_lang(self):
            if not messagebox.askyesno(APP, tr("เปลี่ยนภาษาเป็น English?\n\nโปรแกรมจะเปิดใหม่ (การเชื่อมต่อที่เปิดอยู่จะถูกตัด)")):
                return
            self.cfg["lang"] = "en" if LANG == "th" else "th"
            save_config(self.cfg)
            RESTART.append(True)
            self.quit()

        def cycle_theme(self):
            order = ["auto", "light", "dark"]
            mode = order[(order.index(T.mode) + 1) % 3]
            self.cfg["theme"] = mode
            save_config(self.cfg)
            T.set_mode(mode)
            self.theme_btn.configure(text=self.THEME_LABEL[mode])

        # ---------------- client tab ----------------
        def _build_client(self, P):
            P.columnconfigure(0, weight=5, uniform="c")
            P.columnconfigure(1, weight=5, uniform="c")
            P.rowconfigure(0, weight=1)
            c = card(P)
            c.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            lbl(c, tr("เชื่อมต่อไปยังเครื่องอื่น"), font="h2").pack(anchor="w", padx=22, pady=(20, 2))
            lbl(c, tr("ใส่ ID 9 หลักและรหัสผ่านของเครื่องที่ต้องการควบคุม"),
                fg="muted", font="small", wraplength=400).pack(anchor="w", padx=22, pady=(0, 16))
            lbl(c, tr("ID เครื่องปลายทาง"), fg="muted", font="smallbold").pack(anchor="w", padx=22)
            recent = [fmt_id(i) for i in (parse_id(x) for x in self.cfg.get("recent", [])) if i]
            self.host_var = tk.StringVar(value=recent[0] if recent else "")
            self.host_cb = ttk.Combobox(c, textvariable=self.host_var, values=recent, font=T.f["mono"])
            self.host_cb.pack(fill="x", padx=22, pady=(4, 2))
            self.host_alias = lbl(c, "", fg="accent", font="small")
            self.host_alias.pack(anchor="w", padx=22, pady=(0, 10))
            lbl(c, tr("รหัสผ่าน"), fg="muted", font="smallbold").pack(anchor="w", padx=22)
            pwrow = box(c)
            pwrow.pack(fill="x", padx=22, pady=(4, 8))
            self.cpw_var = tk.StringVar()
            self.cpw_entry = ttk.Entry(pwrow, textvariable=self.cpw_var, show="•", font=T.f["big"])
            self.cpw_entry.pack(side="left", fill="x", expand=True)
            self.cpw_entry.bind("<Return>", lambda e: self.connect())
            self.show_pw_btn = ttk.Button(pwrow, text=tr("👁 แสดง"), width=8, command=self._toggle_pw)
            self.show_pw_btn.pack(side="left", padx=(6, 0))
            self.remember_var = tk.BooleanVar(value=self.cfg.get("remember_pw", True))
            ttk.Checkbutton(c, text=tr("จดจำรหัสผ่านของเครื่องนี้"), variable=self.remember_var,
                            style="Card.TCheckbutton").pack(anchor="w", padx=22)
            self.view_only_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(c, text=tr("ดูหน้าจออย่างเดียว (ไม่ควบคุม)"), variable=self.view_only_var,
                            style="Card.TCheckbutton").pack(anchor="w", padx=22)
            self.conn_btn = ttk.Button(c, text=tr("เชื่อมต่อ   →"), style="Big.Accent.TButton", command=self.connect)
            self.conn_btn.pack(fill="x", padx=22, pady=(16, 10))
            self.cstatus = tk.StringVar(value="")
            lbl(c, textvariable=self.cstatus, fg="warn", font="small", wraplength=400).pack(anchor="w", padx=22)
            tips = box(c)
            tips.pack(side="bottom", fill="x", padx=22, pady=(0, 18))
            for t in (tr("🔒  การเชื่อมต่อทั้งหมดเข้ารหัสอย่างปลอดภัย"),
                      tr("🔑  รหัสผ่านที่จดจำถูกเก็บอย่างปลอดภัยในเครื่องนี้")):
                lbl(tips, t, fg="muted", font="small", wraplength=400).pack(anchor="w", pady=1)
            self.host_var.trace_add("write", lambda *a: self._on_host_change())

            d = card(P)
            d.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
            head = box(d)
            head.pack(fill="x", padx=20, pady=(20, 2))
            lbl(head, tr("เครื่องที่เคยเชื่อมต่อ"), font="h2").pack(side="left")
            ttk.Button(head, text=tr("ล้างทั้งหมด"), style="Tool.TButton", command=self._clear_recent).pack(side="right")
            lbl(d, tr("ดับเบิลคลิกเพื่อรีโมททันที (ถ้าจดจำรหัสผ่านไว้) · คลิกขวาเพื่อดูเมนู"), fg="muted",
                font="small", wraplength=400, justify="left").pack(anchor="w", padx=20, pady=(0, 10))
            tf = box(d)
            tf.pack(fill="both", expand=True, padx=20)
            t = self.recent_tree = ttk.Treeview(tf, columns=("name", "id", "key", "last"), show="headings",
                                                selectmode="browse")
            for col, txt, w, st in (("name", tr("ชื่อเครื่อง"), 170, True), ("id", "ID", 105, False),
                                    ("key", tr("รหัส"), 40, False), ("last", tr("ล่าสุด"), 90, False)):
                t.heading(col, text=txt)
                t.column(col, width=w, stretch=st, anchor="center" if col == "key" else "w")
            t.pack(fill="both", expand=True)
            t.bind("<Double-1>", lambda e: self.connect_recent())
            t.bind("<Return>", lambda e: self.connect_recent())
            t.bind("<<TreeviewSelect>>", self._pick_recent_fill)
            t.bind("<Button-3>", self._recent_menu)
            t.bind("<Button-2>", self._recent_menu)
            t.bind("<Control-Button-1>", self._recent_menu)
            t.bind("<Delete>", lambda e: self.remove_recent())
            t.bind("<F2>", lambda e: self.rename_recent())
            btns = box(d)
            btns.pack(fill="x", padx=20, pady=(10, 20))
            ttk.Button(btns, text=tr("▶  เชื่อมต่อ"), style="Accent.TButton", command=self.connect_recent).pack(side="left")
            ttk.Button(btns, text=tr("✎ เปลี่ยนชื่อ"), command=self.rename_recent).pack(side="left", padx=6)
            ttk.Button(btns, text=tr("✕ ลบ"), command=self.remove_recent).pack(side="left")
            self.recent_menu = tk.Menu(self.root, tearoff=0)
            self.recent_menu.add_command(label=tr("▶  เชื่อมต่อ"), command=self.connect_recent)
            self.recent_menu.add_command(label=tr("✎  เปลี่ยนชื่อ…"), command=self.rename_recent)
            self.recent_menu.add_command(label=tr("⧉  คัดลอก ID"), command=self.copy_recent_id)
            self.recent_menu.add_separator()
            self.recent_menu.add_command(label=tr("🔑  ลืมรหัสผ่าน"), command=self.forget_recent_pw)
            self.recent_menu.add_command(label=tr("✕  ลบออกจากรายการ"), command=self.remove_recent)
            self._refresh_recent()
            self._on_host_change()

        # ----- รหัสผ่าน -----
        def _toggle_pw(self):
            shown = self.cpw_entry.cget("show") == ""
            self.cpw_entry.configure(show="•" if shown else "")
            self.show_pw_btn.configure(text=tr("👁 แสดง") if shown else tr("🙈 ซ่อน"))

        def _recent(self, rid):
            return next((r for r in self.cfg.get("recent_info", []) if r.get("id") == rid), None)

        def _display_name(self, rid, fallback=""):
            r = self._recent(rid) or {}
            return r.get("alias") or r.get("name") or fallback

        def _on_host_change(self):
            rid = parse_id(self.host_var.get())
            if not rid:
                self.host_alias.configure(text="")
                return
            r = self._recent(rid)
            self.host_alias.configure(text=("📌 " + self._display_name(rid)) if r else "")
            pw = secret_get(rid)
            if pw:
                self.cpw_var.set(pw)
                self.remember_var.set(True)
            elif r is not None:
                self.cpw_var.set("")

        # ----- เครื่องที่เคยเชื่อมต่อ -----
        def _refresh_recent(self, select=None):
            t = self.recent_tree
            t.delete(*t.get_children(""))
            for r in self.cfg.get("recent_info", [])[:50]:
                rid = r.get("id", "")
                when = datetime.fromtimestamp(r.get("t", 0)).strftime("%d/%m %H:%M") if r.get("t") else ""
                name = r.get("alias") or r.get("name") or "-"
                t.insert("", "end", iid="r" + rid, values=(name, fmt_id(rid), "🔑" if secret_has(rid) else "", when))
            if select and t.exists("r" + select):
                t.selection_set("r" + select)
                t.see("r" + select)

        def _sel_recent(self):
            sel = self.recent_tree.selection()
            return sel[0][1:] if sel else None

        def _recent_menu(self, e):
            row = self.recent_tree.identify_row(e.y)
            if row:
                self.recent_tree.selection_set(row)
                self.recent_menu.tk_popup(e.x_root, e.y_root)

        def _pick_recent_fill(self, e=None):
            rid = self._sel_recent()
            if rid:
                self.host_var.set(fmt_id(rid))

        def connect_recent(self):
            rid = self._sel_recent()
            if not rid:
                messagebox.showinfo(APP, tr("เลือกเครื่องจากรายการก่อน"))
                return
            self.host_var.set(fmt_id(rid))
            pw = secret_get(rid)
            if pw:
                self.cpw_var.set(pw)
                self.connect()
            else:
                self.cpw_var.set("")
                self.cpw_entry.focus_set()
                self.cstatus.set(tr("ใส่รหัสผ่านของ %s แล้วกดเชื่อมต่อ (ติ๊ก \"จดจำรหัสผ่าน\" เพื่อครั้งหน้ากดครั้งเดียว)")
                                 % self._display_name(rid, fmt_id(rid)))

        def rename_recent(self):
            rid = self._sel_recent()
            if not rid:
                return
            r = self._recent(rid)
            name = simpledialog.askstring(APP, tr("ตั้งชื่อเรียกเครื่อง ID %s\n(เว้นว่าง = ใช้ชื่อจริงของเครื่อง: %s)")
                                          % (fmt_id(rid), r.get("name") or "-"),
                                          initialvalue=r.get("alias") or r.get("name", ""), parent=self.root)
            if name is None:
                return
            name = name.strip()[:60]
            r["alias"] = name if name and name != r.get("name") else ""
            save_config(self.cfg)
            self._refresh_recent(select=rid)
            self._on_host_change()

        def copy_recent_id(self):
            rid = self._sel_recent()
            if rid:
                self.root.clipboard_clear()
                self.root.clipboard_append(fmt_id(rid))

        def forget_recent_pw(self):
            rid = self._sel_recent()
            if rid:
                secret_del(rid)
                self._refresh_recent(select=rid)
                if parse_id(self.host_var.get()) == rid:
                    self.cpw_var.set("")

        def remove_recent(self):
            rid = self._sel_recent()
            if not rid or not messagebox.askyesno(APP, tr("ลบ %s (%s) ออกจากรายการ?\n(รหัสผ่านที่จดจำไว้จะถูกลบด้วย)")
                                                  % (self._display_name(rid, "-"), fmt_id(rid))):
                return
            self.cfg["recent_info"] = [r for r in self.cfg.get("recent_info", []) if r.get("id") != rid]
            self.cfg["recent"] = [x for x in self.cfg.get("recent", []) if parse_id(x) != rid]
            secret_del(rid)
            save_config(self.cfg)
            self.host_cb.configure(values=[fmt_id(x) for x in self.cfg["recent"]])
            self._refresh_recent()

        def _clear_recent(self):
            if not messagebox.askyesno(APP, tr("ล้างรายการเครื่องที่เคยเชื่อมต่อทั้งหมด และรหัสผ่านที่จดจำไว้?")):
                return
            for r in self.cfg.get("recent_info", []):
                secret_del(r.get("id", ""))
            self.cfg.update({"recent": [], "recent_info": []})
            save_config(self.cfg)
            self.host_cb.configure(values=[])
            self._refresh_recent()

        def connect(self):
            rid = parse_id(self.host_var.get())
            pw = self.cpw_var.get()
            if not rid:
                messagebox.showerror(APP, tr("กรุณาใส่ ID 9 หลักของเครื่องปลายทาง\n(ดู ID ได้ที่แท็บ \"ให้เครื่องอื่นควบคุมเครื่องนี้\" ของเครื่องนั้น)"))
                return
            if not pw:
                messagebox.showerror(APP, tr("กรุณาใส่รหัสผ่าน"))
                self.cpw_entry.focus_set()
                return
            addr, key = self._relay_conn()
            if not addr:
                messagebox.showerror(APP, tr("ยังไม่ได้ตั้งค่า Server\nไปที่แท็บ \"ตั้งค่า Server\""))
                return
            relay = {"addr": addr, "key": key, "id": rid, "direct": self._direct_on()}
            host = "ID " + fmt_id(rid)
            label = self._display_name(rid, host)
            remember = self.remember_var.get()
            self.cfg["remember_pw"] = remember
            self.conn_btn.configure(state="disabled")
            self.cstatus.set(tr("กำลังเชื่อมต่อ %s … (ถ้าปลายทางตั้งให้ถามก่อน ต้องรอให้กดยอมรับ)") % label)

            def work():
                try:
                    tls, info, fp = client_connect(host, 0, pw, self._confirm_fp_threadsafe, relay=relay)
                    if remember:
                        secret_set(rid, pw)
                    else:
                        secret_del(rid)
                    self.q.put(("connected", rid, tls, info, fp))
                except socket.timeout:
                    self.q.put(("connect_err", tr("หมดเวลา — ไม่มีการตอบรับจาก %s") % label))
                except OSError as e:
                    msg = err_text(e)
                    if "\u0e23\u0e2b\u0e31\u0e2a\u0e1c\u0e48\u0e32\u0e19" in msg or "password" in msg.lower():
                        secret_del(rid)
                    self.q.put(("connect_err", tr("เชื่อมต่อ %s ไม่ได้: %s") % (label, msg)))
                except Exception as e:
                    self.q.put(("connect_err", tr("เชื่อมต่อ %s ไม่ได้: %s") % (label, err_text(e))))
            threading.Thread(target=work, daemon=True).start()

        # ---------------- server tab ----------------
        def _build_server(self, P):
            P.columnconfigure(0, weight=6, uniform="s")
            P.columnconfigure(1, weight=5, uniform="s")
            P.rowconfigure(0, weight=1)
            left = ttk.Frame(P)
            left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            right = ttk.Frame(P)
            right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

            # สถานะ + ปุ่มเริ่ม
            self.status_card = tk.Frame(left, highlightthickness=1, bd=0)
            self.status_card.pack(fill="x")
            self.banner = tk.Label(self.status_card, font=T.f["status"], anchor="w")
            self.banner.pack(fill="x", padx=20, pady=(16, 0))
            self.banner_sub = tk.Label(self.status_card, font=T.f["small"], anchor="w", justify="left", wraplength=480)
            self.banner_sub.pack(fill="x", padx=20, pady=(2, 10))
            self.status_btns = tk.Frame(self.status_card, bd=0)
            self.status_btns.pack(fill="x", padx=20, pady=(0, 16))
            self.srv_btn = ttk.Button(self.status_btns, text=tr("▶   เริ่มเปิดรับการเชื่อมต่อ"), style="Big.Accent.TButton",
                                      command=self.toggle_server)
            self.srv_btn.pack(side="left")
            self.kick_btn = ttk.Button(self.status_btns, text=tr("ตัดการเชื่อมต่อ"), style="Big.Danger.TButton",
                                       command=self.kick)
            self.host_chat_btn = ttk.Button(self.status_btns, text="💬 " + tr("แชท"), style="Big.TButton",
                                            command=lambda: self.show_host_chat(True))
            self.host_chat = None

            # ข้อมูลสำหรับเชื่อมต่อ
            info = card(left)
            info.pack(fill="x", pady=(14, 0))
            lbl(info, tr("ข้อมูลสำหรับให้อีกฝั่งเชื่อมต่อ"), font="h2").grid(row=0, column=0, columnspan=3, sticky="w",
                                                                    padx=20, pady=(16, 10))
            lbl(info, tr("ID ของเครื่องนี้"), fg="muted", font="smallbold").grid(row=1, column=0, columnspan=2,
                                                                         sticky="w", padx=20)
            self.id_lbl = lbl(info, "", fg="accent", font="monobig")
            self.id_lbl.grid(row=2, column=0, columnspan=2, sticky="nw", padx=20)
            self.relay_state_lbl = lbl(info, "", fg="muted", font="small", wraplength=460)
            self.relay_state_lbl.grid(row=3, column=0, columnspan=2, sticky="nw", padx=20)
            lbl(info, tr("รหัสผ่าน"), fg="muted", font="smallbold").grid(row=4, column=0, columnspan=2, sticky="w",
                                                                   padx=20, pady=(12, 0))
            pwrow = box(info)
            pwrow.grid(row=5, column=0, columnspan=2, sticky="we", padx=20, pady=(4, 18))
            self.spw_var = tk.StringVar(value=self.cfg.get("password") or gen_password())
            self.spw_var.trace_add("write", lambda *a: self._password_changed())
            ttk.Entry(pwrow, textvariable=self.spw_var, font=T.f["mono"], width=16).pack(side="left", fill="x",
                                                                                          expand=True)
            ttk.Button(pwrow, text=tr("สุ่มใหม่"), command=lambda: self.spw_var.set(gen_password())).pack(side="left",
                                                                                                      padx=(8, 0))
            ttk.Button(pwrow, text=tr("คัดลอก"), command=self._copy_conn).pack(side="left", padx=(6, 0))
            info.columnconfigure(0, weight=1)
            info.columnconfigure(1, weight=1)

            # ตัวเลือก
            opt = card(left)
            opt.pack(fill="x", pady=(14, 0))
            lbl(opt, tr("ตัวเลือก"), font="h2").grid(row=0, column=0, columnspan=2, sticky="w", padx=20, pady=(16, 6))
            self.ask_var = tk.BooleanVar(value=self.cfg.get("ask", True))
            self.allow_var = tk.BooleanVar(value=self.cfg.get("allow_control", True))
            self.files_var = tk.BooleanVar(value=self.cfg.get("allow_files", True))
            for i, (txt, var) in enumerate(((tr("ถามก่อนรับการเชื่อมต่อ"), self.ask_var),
                                            (tr("อนุญาตให้ควบคุมเมาส์/คีย์บอร์ด"), self.allow_var),
                                            (tr("อนุญาตให้รับ-ส่งไฟล์"), self.files_var))):
                ttk.Checkbutton(opt, text=txt, variable=var, style="Card.TCheckbutton",
                                command=self._save_server_opts).grid(row=1 + i, column=0, columnspan=2, sticky="w", padx=20,
                                                                     pady=1)
            lbl(opt, "").grid(row=4, column=0, pady=4)
            opt.columnconfigure(1, weight=1)

            # สิทธิ์ macOS
            self.perm_rows = {}
            if SYSTEM == "Darwin":
                pc = card(right)
                pc.pack(fill="x", pady=(0, 14))
                lbl(pc, tr("สิทธิ์ของ macOS"), font="h2").grid(row=0, column=0, columnspan=3, sticky="w",
                                                          padx=20, pady=(16, 0))
                lbl(pc, tr("ให้สิทธิ์กับแอป %s") % ("NetRemote" if getattr(sys, "frozen", False) else "Terminal"),
                    fg="muted", font="small").grid(row=1, column=0, columnspan=3, sticky="w", padx=20, pady=(0, 8))
                for i, (k, label) in enumerate((("screen", tr("Screen Recording\nให้อีกฝั่งเห็นหน้าจอ")),
                                                ("access", tr("Accessibility\nให้อีกฝั่งควบคุมได้")))):
                    st = lbl(pc, "…", font="smallbold", padx=8, pady=2, anchor="center")
                    st.grid(row=2 + i, column=0, sticky="w", padx=(20, 8), pady=4)
                    lbl(pc, label, font="small").grid(row=2 + i, column=1, sticky="w")
                    ttk.Button(pc, text=tr("เปิดการตั้งค่า"), command=lambda k=k: self._open_perm(k)).grid(
                        row=2 + i, column=2, sticky="e", padx=20, pady=4)
                    self.perm_rows[k] = st
                lbl(pc, "").grid(row=4, column=0, pady=4)
                pc.columnconfigure(1, weight=1)
                self._check_perms()

            lc = card(right)
            lc.pack(fill="both", expand=True)
            lbl(lc, tr("บันทึกเหตุการณ์"), font="h2").pack(anchor="w", padx=20, pady=(16, 8))
            self.log = T.track(tk.Listbox(lc, activestyle="none", relief="flat", highlightthickness=0, bd=0,
                                          font=T.f["small"]),
                               bg="card", fg="text", selectbackground="sel", selectforeground="text")
            self.log.pack(fill="both", expand=True, padx=20)
            try:
                fp = server_fingerprint() if os.path.exists(CERT_FILE) else tr("(สร้างเมื่อเริ่มเปิดรับครั้งแรก)")
            except Exception:
                fp = "-"
            self.fp_lbl = lbl(lc, "Certificate  %s" % fp[:47], fg="muted", font="small")
            self.fp_lbl.pack(anchor="w", padx=20, pady=(8, 14))
            self._banner("off")

        # ---------------- relay tab ----------------
        def _build_relay(self, P):
            P.columnconfigure(0, weight=6, uniform="r")
            P.columnconfigure(1, weight=5, uniform="r")
            P.rowconfigure(0, weight=1)
            left = ttk.Frame(P)
            left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            f = card(left)
            f.pack(fill="x")
            lbl(f, tr("ตั้งค่า Server"), font="h2").pack(anchor="w", padx=22, pady=(20, 2))
            lbl(f, tr("ใส่ที่อยู่ Server และ Server Key ที่ได้รับจากผู้ดูแลระบบ"),
                fg="muted", font="small", wraplength=470).pack(anchor="w", padx=22, pady=(0, 14))
            locked = bool(env_str("RELAY_ADDR"))
            lbl(f, tr("ที่อยู่ Server"), fg="muted", font="smallbold").pack(anchor="w", padx=22)
            self.relay_addr_var = tk.StringVar(value=self._relay_conn()[0])
            e1 = ttk.Entry(f, textvariable=self.relay_addr_var, font=T.f["big"])
            e1.pack(fill="x", padx=22, pady=(4, 2))
            lbl(f, tr("เช่น relay.example.com:5910 หรือ 203.0.113.10:5910"), fg="muted", font="small").pack(
                anchor="w", padx=22, pady=(0, 10))
            lbl(f, "Server Key", fg="muted", font="smallbold").pack(anchor="w", padx=22)
            self.relay_key_var = tk.StringVar(value=self._relay_conn()[1])
            e2 = ttk.Entry(f, textvariable=self.relay_key_var, show="•", font=T.f["big"])
            e2.pack(fill="x", padx=22, pady=(4, 8))
            if locked:
                e1.configure(state="disabled")
                e2.configure(state="disabled")
                lbl(f, tr("🔒  ตั้งค่าไว้โดยผู้ดูแลระบบ"), fg="accent", font="smallbold").pack(
                    anchor="w", padx=22)
            row = box(f)
            row.pack(fill="x", padx=22, pady=(12, 6))
            b = ttk.Button(row, text=tr("บันทึก"), style="Accent.TButton", command=self.save_relay)
            b.pack(side="left")
            if locked:
                b.configure(state="disabled")
            ttk.Button(row, text=tr("ทดสอบการเชื่อมต่อ"), command=self.test_relay).pack(side="left", padx=8)
            self.relay_test_var = tk.StringVar(value="")
            lbl(f, textvariable=self.relay_test_var, fg="muted", font="small", wraplength=470).pack(
                anchor="w", padx=22, pady=(0, 16))

            uc = card(left)
            uc.pack(fill="both", expand=True, pady=(14, 0))
            head = box(uc)
            head.pack(fill="x", padx=22, pady=(18, 4))
            lbl(head, tr("อัปเดตโปรแกรม"), font="h2").pack(side="left")
            ttk.Button(head, text=tr("ตรวจสอบอัปเดต"), command=lambda: self.check_updates(manual=True)).pack(side="right")
            lbl(uc, tr("เวอร์ชันที่ใช้อยู่: %s") % VERSION, fg="muted", font="small").pack(
                anchor="w", padx=22)
            self.upd_status = lbl(uc, tr("ยังไม่ได้ตรวจสอบ"), fg="muted", font="smallbold", wraplength=470)
            self.upd_status.pack(anchor="w", padx=22, pady=(6, 2))
            self.upd_notes = lbl(uc, "", fg="text", font="small", wraplength=470)
            self.upd_notes.pack(anchor="w", padx=22)
            self.upd_btn = ttk.Button(uc, text=tr("⬇  ดาวน์โหลดเวอร์ชันใหม่"), style="Accent.TButton",
                                      command=self.download_update)
            self.upd_progress = ttk.Progressbar(uc, mode="determinate", maximum=100)
            self.update_info = None
            self.upd_cancel = None
            self.update_ready = None
            self.upd_auto = False

            right = ttk.Frame(P)
            right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
            idc = card(right)
            idc.pack(fill="x")
            lbl(idc, tr("ID ของเครื่องนี้"), font="h2").pack(anchor="w", padx=22, pady=(20, 2))
            lbl(idc, tr("ให้อีกฝั่งใส่ ID นี้เพื่อเชื่อมต่อเข้ามา"), fg="muted", font="small").pack(anchor="w", padx=22)
            self.relay_id_lbl = lbl(idc, fmt_id(self.cfg["host_id"]), fg="accent", font="monobig")
            self.relay_id_lbl.pack(anchor="w", padx=22, pady=(10, 8))
            ttk.Button(idc, text=tr("สร้าง ID ใหม่"), command=self.new_id).pack(anchor="w", padx=22, pady=(0, 20))

            st = card(right)
            st.pack(fill="both", expand=True, pady=(14, 0))
            lbl(st, tr("สถานะการเชื่อมต่อ Server"), font="h2").grid(row=0, column=0, columnspan=2, sticky="w",
                                                             padx=22, pady=(18, 10))
            self.rs = {}
            for i, (k, t) in enumerate((("state", tr("สถานะ")), ("addr", "Server"), ("detail", tr("รายละเอียด")),
                                        ("host", tr("รับการเชื่อมต่อของเครื่องนี้")), ("checked", tr("ตรวจล่าสุด")))):
                lbl(st, t, fg="muted", font="small").grid(row=i + 1, column=0, sticky="w", padx=(22, 12), pady=2)
                v = lbl(st, "–", font="smallbold" if k == "state" else "small", padx=8 if k == "state" else 0,
                        pady=2 if k == "state" else 0)
                v.grid(row=i + 1, column=1, sticky="w", pady=2)
                self.rs[k] = v
            st.columnconfigure(1, weight=1)


        # ----- อัปเดตโปรแกรม -----
        def _update_loop(self):
            self.check_updates(manual=False)
            self.root.after(3600 * 1000, self._update_loop)              # ตรวจทุก 1 ชั่วโมง

        def check_updates(self, manual=False):
            addr, key = self._relay_conn()
            if not addr:
                if manual:
                    self.upd_status.configure(text=tr("ยังไม่ได้ตั้งค่า Server"), fg=T.c("danger"))
                return
            if self.upd_cancel is not None or self.update_ready:
                return                                                      # กำลังดาวน์โหลด / พร้อมติดตั้งแล้ว
            if manual:
                self.upd_status.configure(text=tr("กำลังตรวจสอบ…"), fg=T.c("muted"))

            def work():
                try:
                    self.q.put(("update_info", relay_update_info(addr, key), manual))
                except Exception as e:
                    self.q.put(("update_info", e, manual))
            threading.Thread(target=work, daemon=True).start()

        def _badge(self, text, color="#F59E0B", fg="#1F1300"):
            if text:
                self.update_badge.configure(text=text, bg=color, fg=fg)
                self.update_badge.pack(side="right", padx=(0, 8))
            else:
                self.update_badge.pack_forget()

        def _on_update_info(self, info, manual):
            self.upd_btn.pack_forget()
            if isinstance(info, Exception):
                if manual:
                    self.upd_status.configure(text=tr("✗ ตรวจสอบไม่ได้: %s") % err_text(info), fg=T.c("danger"))
                return
            self.update_info = info
            latest = info.get("version")
            if not latest or version_tuple(latest) <= version_tuple(VERSION):
                self.upd_status.configure(text=tr("✓ ใช้เวอร์ชันล่าสุดอยู่แล้ว (%s)") % VERSION, fg=T.c("ok"))
                self.upd_notes.configure(text="")
                self._badge(None)
                return
            plat = update_plat_for(info)
            has_file = plat in (info.get("files") or {})
            self.upd_notes.configure(text=info.get("notes") or "")
            if has_file and can_auto_install(info):
                self.upd_status.configure(text=tr("⬆ มีเวอร์ชันใหม่ %s — กำลังดาวน์โหลดอัตโนมัติ…") % latest,
                                          fg=T.c("warn"))
                self._badge(tr("⬇  กำลังดาวน์โหลดอัปเดต %s") % latest)
                self.download_update(auto=True)
                return
            self.upd_status.configure(text=tr("⬆ มีเวอร์ชันใหม่: %s  (ใช้อยู่ %s)") % (latest, VERSION), fg=T.c("warn"))
            if has_file:
                f = info["files"][plat]
                self.upd_btn.configure(text=tr("⬇  ดาวน์โหลด %s (%s)") % (f["name"], fmt_size(f["size"])),
                                       state="normal", command=self.download_update)
                self.upd_btn.pack(anchor="w", padx=22, pady=(10, 18))
            elif info.get("url"):
                self.upd_btn.configure(text=tr("🌐  เปิดหน้าดาวน์โหลด"), state="normal", command=self.download_update)
                self.upd_btn.pack(anchor="w", padx=22, pady=(10, 18))
            else:
                self.upd_notes.configure(text=(info.get("notes") or "") + ("\n" if info.get("notes") else "") +
                                         tr("(ยังไม่มีไฟล์สำหรับเครื่องนี้ — ติดต่อผู้ดูแลระบบ)"))
            self._badge(tr("⬆  มีอัปเดต %s") % latest)
            if not manual and getattr(self, "_notified_ver", None) != latest:
                self._notified_ver = latest
                self._log(tr("⬆ มีโปรแกรมเวอร์ชันใหม่ %s — ดูที่แท็บ \"ตั้งค่า Server\"") % latest)

        def download_update(self, auto=False):
            info = self.update_info or {}
            plat = update_plat_for(info)
            f = (info.get("files") or {}).get(plat)
            if not f:
                if info.get("url"):
                    import webbrowser
                    webbrowser.open(info["url"])
                return
            if self.upd_cancel is not None:
                self.upd_cancel.set()
                return
            addr, key = self._relay_conn()
            self.upd_auto = auto
            if auto:
                dest = UPDATE_DIR
                shutil.rmtree(dest, ignore_errors=True)
            else:
                dest = os.path.join(os.path.expanduser("~"), "Downloads")
            self.upd_cancel = threading.Event()
            self.upd_btn.configure(text=tr("ยกเลิกการดาวน์โหลด"), command=self.download_update)
            if not auto:
                self.upd_btn.pack(anchor="w", padx=22, pady=(10, 0))
            self.upd_progress.configure(value=0)
            self.upd_progress.pack(fill="x", padx=22, pady=(8, 18))

            def prog(got, total):
                self.q.put(("update_progress", got, total))

            def work():
                try:
                    path = relay_update_download(addr, key, plat, dest, prog, self.upd_cancel)
                    self.q.put(("update_done", path))
                except Exception as e:
                    self.q.put(("update_done", e))
            threading.Thread(target=work, daemon=True).start()

        def _on_update_done(self, res):
            self.upd_cancel = None
            self.upd_progress.pack_forget()
            self.upd_btn.pack_forget()
            latest = (self.update_info or {}).get("version", "")
            if isinstance(res, Exception):
                self.upd_status.configure(text=tr("✗ ดาวน์โหลดไม่สำเร็จ: %s") % err_text(res), fg=T.c("danger"))
                self._badge(tr("⬆  มีอัปเดต %s") % latest)
                return
            if self.upd_auto:
                self.update_ready = res
                self.upd_status.configure(text=tr("✓ เวอร์ชัน %s พร้อมติดตั้ง — จะติดตั้งให้เมื่อปิดโปรแกรม") % latest,
                                          fg=T.c("ok"))
                self.upd_btn.configure(text=tr("↻  รีสตาร์ตและอัปเดตตอนนี้"), state="normal",
                                       command=self.install_update)
                self.upd_btn.pack(anchor="w", padx=22, pady=(10, 18))
                self._badge(tr("↻  รีสตาร์ตเพื่ออัปเดตเป็น %s") % latest, "#15803D", "#FFFFFF")
                self._log(tr("⬆ ดาวน์โหลดเวอร์ชัน %s แล้ว — กดปุ่มด้านบนเพื่อรีสตาร์ต หรือจะติดตั้งให้เมื่อปิดโปรแกรม") % latest)
                if env_str("AUTO_UPDATE", "").lower() in ("auto", "1", "true", "yes", "on"):
                    self._auto_install_when_idle()
                return
            self.upd_status.configure(text=tr("✓ ดาวน์โหลดเรียบร้อย: %s") % os.path.basename(res), fg=T.c("ok"))
            if SYSTEM == "Darwin":
                how = (tr("เปิดไฟล์ติดตั้งให้แล้ว → ปิดโปรแกรมนี้ แล้วลาก NetRemote ไปไว้ใน Applications")
                       if res.endswith(".dmg") else tr("ปิดโปรแกรมนี้ แล้วใช้ไฟล์ใหม่แทนตัวเดิม"))
                subprocess.Popen(["open", res] if res.endswith(".dmg") else ["open", "-R", res])
            elif SYSTEM == "Windows":
                how = tr("ปิดโปรแกรมนี้ แล้วใช้ไฟล์ %s แทนไฟล์ NetRemote.exe ตัวเดิม") % os.path.basename(res)
                subprocess.Popen(["explorer", "/select,", res])
            else:
                how = tr("ไฟล์อยู่ที่ %s") % res
                open_path(os.path.dirname(res))
            messagebox.showinfo(APP, tr("ดาวน์โหลดเวอร์ชันใหม่เรียบร้อย\n\n%s") % how)

        def _busy(self):
            """มีการรีโมทอยู่หรือไม่ (ทั้งควบคุมเครื่องอื่น และถูกควบคุม)"""
            return bool(self.viewers) or bool(self.server and self.server.is_alive() and self.server.session)

        def _auto_install_when_idle(self):
            """AUTO_UPDATE=auto — สำหรับเครื่องที่ไม่มีคนเฝ้า: ติดตั้งทันทีเมื่อไม่มีการรีโมท"""
            if not self.update_ready:
                return
            if self._busy():
                self.root.after(30000, self._auto_install_when_idle)
                return
            self.install_update(confirm=False)

        def install_update(self, confirm=True):
            if not self.update_ready:
                return
            latest = (self.update_info or {}).get("version", "")
            if confirm:
                msg = tr("รีสตาร์ตโปรแกรมเพื่ออัปเดตเป็นเวอร์ชัน %s ตอนนี้?") % latest
                if self._busy():
                    msg += "\n\n" + tr("การรีโมทที่เปิดอยู่จะถูกตัด")
                if not messagebox.askyesno(APP, msg):
                    return
            try:
                launch_installer(self.update_ready, relaunch=True)
            except Exception as e:
                messagebox.showerror(APP, tr("ติดตั้งอัปเดตไม่สำเร็จ: %s") % err_text(e))
                return
            self.update_ready = None
            self._log(tr("กำลังอัปเดตเป็นเวอร์ชัน %s …") % latest)
            self.quit(installing=True)

        def _confirm_fp_threadsafe(self, host, fp, name):
            """ตรวจ Certificate ของปลายทาง (เรียกจาก thread เชื่อมต่อ) — ครั้งแรกจดจำไว้ ถ้าเปลี่ยนจะถามผู้ใช้"""
            known = self.cfg.setdefault("known", {})
            old = known.get(host)
            if old == fp:
                return True
            if old is None:
                known[host] = fp
                save_config(self.cfg)
                return True
            ev, box = threading.Event(), {}
            self.q.put(("ask_fp", host, old, fp, name, ev, box))
            ev.wait(120)
            if box.get("ok"):
                known[host] = fp
                save_config(self.cfg)
            return bool(box.get("ok"))

        def _relay_conn(self):
            """ที่อยู่และ Key ของ Relay — จาก .env ก่อน ถ้าไม่มีใช้ค่าที่ตั้งในโปรแกรม"""
            if env_str("RELAY_ADDR"):
                return env_str("RELAY_ADDR").strip(), ENV.get("RELAY_KEY", "")
            return self.cfg.get("relay_addr", "").strip(), self.cfg.get("relay_key", "")

        def save_relay(self, quiet=False):
            if env_str("RELAY_ADDR"):
                return True
            addr = self.relay_addr_var.get().strip()
            if addr:
                try:
                    parse_hostport(addr, RELAY_PORT)
                except ValueError:
                    messagebox.showerror(APP, tr("รูปแบบที่อยู่ Server ไม่ถูกต้อง (เช่น relay.example.com:5910)"))
                    return False
            self.cfg.update({"relay_addr": addr, "relay_key": self.relay_key_var.get()})
            save_config(self.cfg)
            self._update_id_row()
            self.monitor.refresh()
            if not quiet:
                self.relay_test_var.set(tr("บันทึกแล้ว — กำลังเชื่อมต่อ Server ใหม่"))
                self.restart_server()
            return True

        def restart_server(self):
            """เริ่มรับการเชื่อมต่อใหม่ด้วยการตั้งค่าล่าสุด (ทำอัตโนมัติ)"""
            if self.server and self.server.is_alive():
                self.server.stop()
                self.server = None
            self.root.after(400, lambda: self.start_server(auto=True))

        def test_relay(self):
            if not self.save_relay(quiet=True):
                return
            addr, key = self._relay_conn()
            self.monitor.refresh()
            if not addr:
                self.relay_test_var.set(tr("ใส่ที่อยู่ Server ก่อน"))
                return
            self.relay_test_var.set(tr("กำลังทดสอบ %s …") % addr)

            def work():
                try:
                    r = relay_test(addr, key)
                    msg = tr("✓ เชื่อมต่อ Server ได้ ใช้งานได้ปกติ")
                except Exception as e:
                    msg = "✗ %s" % err_text(e)
                self.q.put(("relay_test", msg))
            threading.Thread(target=work, daemon=True).start()

        def new_id(self):
            if not messagebox.askyesno(APP, tr("สร้าง ID ใหม่? ผู้ที่เคยเชื่อมต่อด้วย ID เดิมจะต้องใช้ ID ใหม่")):
                return
            self.cfg.update({"host_id": new_host_id(), "host_secret": secrets.token_hex(24)})
            save_config(self.cfg)
            self.relay_id_lbl.configure(text=fmt_id(self.cfg["host_id"]))
            self._update_id_row()
            self.restart_server()

        def _relay_cfg(self):
            addr, key = self._relay_conn()
            if addr:
                return {"addr": addr, "key": key, "id": self.cfg["host_id"], "secret": self.cfg["host_secret"],
                        "direct": self._direct_on(), "direct_port": direct_port()}
            return None


        def _direct_on(self):
            return env_bool("DIRECT_CONNECT", True)          # เชื่อมต่อตรงอัตโนมัติเสมอ (ผู้ดูแลปิดได้ใน .env)

        def _update_id_row(self, state=None, text=None):
            self.id_lbl.configure(text=fmt_id(self.cfg["host_id"]), fg=T.c("accent"))
            if state:
                self.relay_state["host"] = state
                self.relay_state["host_text"] = text or ""
            running = bool(self.server and self.server.is_alive())
            if not self._relay_cfg():
                self.relay_state_lbl.configure(text=tr("ยังไม่ได้ตั้งค่า Server — ตั้งที่แท็บ \"ตั้งค่า Server\""),
                                               fg=T.c("danger"))
            elif text and running:
                color = {"online": "ok", "error": "danger", "connecting": "warn"}.get(state, "muted")
                self.relay_state_lbl.configure(text=("● " if state == "online" else "") + text, fg=T.c(color))
            elif not running:
                self.relay_state["host"] = None
                self.relay_state_lbl.configure(text=tr("หยุดรับการเชื่อมต่ออยู่ — กด \"เริ่มเปิดรับการเชื่อมต่อ\""), fg=T.c("muted"))
            self._render_relay()

        def _render_relay(self):
            rs = self.relay_state
            mon, d = rs["mon"], rs["data"]
            if mon == "unset":
                txt, bg = tr("○  ยังไม่ได้ตั้งค่า Server"), "#6B7280"
            elif mon == "error":
                txt, bg = tr("●  Server: เชื่อมต่อไม่ได้"), "#DC2626"
            elif mon == "ok":
                txt, bg = tr("●  เชื่อมต่อ Server แล้ว"), "#15803D"
                if rs["host"] == "online":
                    txt += tr(" · พร้อมรับการเชื่อมต่อ")
            else:
                txt, bg = tr("●  Server: กำลังเชื่อมต่อ…"), "#B45309"
            self.relay_pill.configure(text=txt, bg=bg)
            if not hasattr(self, "rs"):
                return
            pills = {"ok": (tr("✓ ออนไลน์"), "ok"), "error": (tr("✗ เชื่อมต่อไม่ได้"), "danger"),
                     "unset": (tr("ยังไม่ได้ตั้งค่า"), "muted"), "checking": (tr("กำลังตรวจสอบ…"), "warn")}
            t, c = pills.get(mon, pills["checking"])
            self.rs["state"].configure(text=t, fg=T.c(c), bg=T.c(c + "_bg") if c in ("ok", "danger", "warn") else T.c("subtle"))
            addr = self._relay_conn()[0]
            self.rs["addr"].configure(text=addr or "–")
            if mon == "ok":
                self.rs["detail"].configure(text=tr("ใช้งานได้ปกติ"), fg=T.c("text"))
            elif mon == "error":
                self.rs["detail"].configure(text=str(d or "–"), fg=T.c("danger"), wraplength=300, justify="left")
            else:
                self.rs["detail"].configure(text="–", fg=T.c("text"))
            host = rs["host"]
            running = bool(self.server and self.server.is_alive())
            self.rs["host"].configure(
                text=(tr("● ออนไลน์ — ID %s") % fmt_id(self.cfg["host_id"])) if host == "online" and running else
                (rs["host_text"] if running and rs["host_text"] else tr("หยุดรับการเชื่อมต่ออยู่")),
                fg=T.c("ok" if host == "online" and running else ("danger" if host == "error" and running else "muted")))
            if rs["t"]:
                self.rs["checked"].configure(text=datetime.fromtimestamp(rs["t"]).strftime("%H:%M:%S"))

        def _copy_conn(self):
            txt = tr("NetRemote — ID: %s  รหัสผ่าน: %s") % (fmt_id(self.cfg["host_id"]), self.spw_var.get())
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self._log(tr("คัดลอกข้อมูลการเชื่อมต่อแล้ว"))

        def _open_perm(self, k):
            if k == "screen":
                mac_request_screen_access()
            mac_open_settings(k)

        def _check_perms(self):
            scr, acc = mac_permissions()
            for k, v in (("screen", scr), ("access", acc)):
                lbl = self.perm_rows.get(k)
                if lbl is not None:
                    lbl.configure(text=tr("✓ อนุญาตแล้ว") if v else (tr("✗ ยังไม่อนุญาต") if v is False else tr("? ตรวจไม่ได้")),
                                  fg=T.c("ok" if v else "danger"), bg=T.c("ok_bg" if v else "danger_bg"))
            self.root.after(3000, self._check_perms)

        def _password_changed(self):
            pw = self.spw_var.get().strip()
            if len(norm_pw(pw)) >= 6:
                self.cfg["password"] = pw
                save_config(self.cfg)
                if self.server:
                    self.server.password = pw          # มีผลกับการเชื่อมต่อครั้งถัดไปทันที

        def _save_server_opts(self):
            self.cfg.update({"ask": self.ask_var.get(), "allow_control": self.allow_var.get(),
                             "allow_files": self.files_var.get()})
            save_config(self.cfg)
            if self.server:
                self.server.allow_control = self.allow_var.get()
                self.server.allow_files = self.files_var.get()
                self.server.ask_cb = self._ask_threadsafe if self.ask_var.get() else None

        def _log(self, text):
            self.log.insert(0, "%s  %s" % (datetime.now().strftime("%H:%M:%S"), text))
            if self.log.size() > 300:
                self.log.delete(300, "end")

        def toggle_server(self):
            if self.server and self.server.is_alive():
                self.server.stop()
                self.server = None
                self.srv_btn.configure(text=tr("▶  เริ่มเปิดรับการเชื่อมต่อ"))
                self._banner("off")
                self._update_id_row()
                return
            self.start_server()

        def start_server(self, auto=False):
            """auto=True: เรียกตอนเปิดโปรแกรม/เปลี่ยนการตั้งค่า — ไม่เด้งหน้าต่างแจ้งเตือน แสดงในการ์ดสถานะแทน"""
            if self.server and self.server.is_alive():
                return

            def problem(msg):
                if auto:
                    self._banner("off", sub="⚠ " + msg.replace("\n\n", " — ").replace("\n", " "))
                    self._log("⚠ " + msg.replace("\n", " "))
                else:
                    messagebox.showerror(APP, msg)
            miss = missing_modules(server=True)
            if miss:
                problem(tr("โปรแกรมติดตั้งไม่สมบูรณ์ — กรุณาติดตั้งโปรแกรมใหม่ หรือติดต่อผู้ดูแลระบบ"))
                sys.stderr.write("missing modules: %s\n" % ", ".join(miss))
                return
            pw = self.spw_var.get().strip()
            if len(norm_pw(pw)) < 6:
                if auto and not pw:
                    pw = gen_password()
                    self.spw_var.set(pw)
                else:
                    problem(tr("รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร"))
                    return
            if not self._relay_cfg():
                problem(tr("ยังไม่ได้ตั้งค่า Server\n\nไปที่แท็บ \"ตั้งค่า Server\""))
                return
            self.cfg.update({"password": pw})
            save_config(self.cfg)
            try:
                self.server = Server(0, pw, self.q, self._ask_threadsafe if self.ask_var.get() else None,
                                     self.allow_var.get(), self.files_var.get(), relay=self._relay_cfg())
            except Exception as e:
                messagebox.showerror(APP, tr("เริ่มไม่ได้: %s") % err_text(e))
                return
            self.fp_lbl.configure(text="")
            self.server.start()
            self.srv_btn.configure(text=tr("■  หยุดเปิดรับ"))
            self._banner("wait")
            self._update_id_row()
            if SYSTEM == "Darwin":
                scr, acc = mac_permissions()
                if scr is False:
                    mac_request_screen_access()
                    self._log(tr("⚠ ยังไม่ได้อนุญาต Screen Recording — อีกฝั่งจะเห็นแค่ภาพพื้นหลัง"))
                if acc is False:
                    self._log(tr("⚠ ยังไม่ได้อนุญาต Accessibility — อีกฝั่งจะควบคุมไม่ได้"))

        def kick(self):
            if self.server:
                self.server.kick()

        def _banner(self, state, who="", sub=None):
            self.banner_state = (state, who)
            if state == "off":
                bg, fg, border = "card", "muted", "border"
                title = tr("○   หยุดรับการเชื่อมต่อชั่วคราว") if not sub else tr("○   ยังไม่พร้อมรับการเชื่อมต่อ")
                sub = sub or tr("กด \"เริ่มเปิดรับการเชื่อมต่อ\" เพื่อให้เครื่องอื่นเชื่อมต่อเข้ามาได้อีกครั้ง")
            elif state == "wait":
                bg, fg, border = "ok_bg", "ok", "ok_bg"
                title = tr("●   พร้อมรับการเชื่อมต่อ")
                sub = tr("รอการเชื่อมต่อ — ID %s") % fmt_id(self.cfg["host_id"])
            else:
                self.session_who = who
                bg, fg, border = "danger_bg", "danger", "danger_bg"
                title = tr("●   กำลังถูกควบคุมอยู่")
                sub = sub or tr("โดย %s") % who
            for w in (self.status_card, self.status_btns):
                w.configure(bg=T.c(bg))
            self.status_card.configure(highlightbackground=T.c(border), highlightcolor=T.c(border))
            self.banner.configure(text=title, bg=T.c(bg), fg=T.c(fg))
            self.banner_sub.configure(text=sub, bg=T.c(bg), fg=T.c("text" if state != "off" else "muted"))
            running = state != "off"
            self.srv_btn.configure(text=tr("■   หยุดเปิดรับ") if running else tr("▶   เริ่มเปิดรับการเชื่อมต่อ"),
                                   style="Big.TButton" if running else "Big.Accent.TButton")
            if state == "busy":
                self.kick_btn.pack(side="left", padx=(10, 0))
                if self.host_chat is not None:
                    self.host_chat_btn.pack(side="left", padx=(10, 0))
            else:
                self.kick_btn.pack_forget()
                self.host_chat_btn.pack_forget()

        # ----- แชทฝั่งเครื่องที่ถูกควบคุม -----
        def _open_host_chat(self, chat, call, name):
            self._close_host_chat()
            w = T.track(tk.Toplevel(self.root), bg="card")
            w.title("%s — %s" % (name, APP))
            sw, sh = w.winfo_screenwidth(), w.winfo_screenheight()
            ww, wh = max(340, sw // 7), min(720, sh - 140)
            w.geometry("%dx%d+%d+%d" % (ww, wh, sw - ww - 24, 80))
            w.minsize(320, 420)
            w.protocol("WM_DELETE_WINDOW", w.withdraw)
            panel = ChatPanel(w, chat, call, name, mode="host", width=ww, on_hide=w.withdraw,
                              subtitle=tr("กำลังควบคุมเครื่องนี้"))
            panel.frame.pack(fill="both", expand=True)
            panel.on_unread = self._host_unread
            w.withdraw()
            self.host_chat = (w, panel)
            self._show_control_banner(name)
            if self.banner_state[0] == "busy":
                self.host_chat_btn.pack(side="left", padx=(10, 0))

        def _host_unread(self, n, ev=None):
            if n == -1 or n:
                self.show_host_chat(True)              # ข้อความ/สายเข้า → เด้งหน้าต่างแชทขึ้นมา (นับว่าอ่านแล้ว)
            else:
                self._banner_count(0)

        # ----- แถบแดงด้านบนจอ: "X กำลังควบคุมเครื่องนี้" -----
        def _show_control_banner(self, name):
            self._hide_control_banner()
            if not env_bool("CONTROL_BANNER", True):
                return
            b = tk.Toplevel(self.root)
            b.overrideredirect(True)
            try:
                b.attributes("-topmost", True)
            except tk.TclError:
                pass
            RED = "#DC2626"
            H = 44
            f = T.f["smallbold"]
            text = tr("%s กำลังควบคุมเครื่องนี้") % name
            chat_w = max(84, f.measure(tr("แชท") + " (99)") + 46)
            disc_w = f.measure(tr("ตัดการเชื่อมต่อ")) + 30
            W = 22 + 12 + 8 + f.measure(text) + 16 + chat_w + 6 + disc_w + 6
            c = tk.Canvas(b, width=W, height=H, highlightthickness=0, bd=0, bg=RED)
            c.pack()
            c.create_oval(18, H / 2 - 5, 28, H / 2 + 5, fill="#FFFFFF", outline="")
            c.create_text(38, H / 2, text=text, anchor="w", fill="#FFFFFF", font=f)
            x = 38 + f.measure(text) + 16
            self.banner_chat = RoundButton(c, "chat", text=tr("แชท"), kind="dark", w=chat_w, h=32, r=16, bg=RED,
                                           icon_px=15, command=lambda: self.show_host_chat(True))
            KIND["banner_w"] = ("#FFFFFF", "#FDECEC", RED)
            disc = RoundButton(c, None, text=tr("ตัดการเชื่อมต่อ"), kind="banner_w", w=disc_w, h=32, r=16, bg=RED,
                               command=self.kick)
            c.create_window(x, H / 2, window=self.banner_chat.cv, anchor="w")
            c.create_window(x + chat_w + 6, H / 2, window=disc.cv, anchor="w")
            sw = b.winfo_screenwidth()
            b.geometry("%dx%d+%d+%d" % (W, H, (sw - W) // 2, 6))
            # มุมมน: macOS ใช้พื้นโปร่งใส, Windows ใช้สีโปร่งใส
            try:
                if SYSTEM == "Darwin":
                    b.attributes("-transparent", True)
                    b.configure(bg="systemTransparent")
                    c.configure(bg="systemTransparent")
                    c.create_image(0, 0, anchor="nw", image=shape_img(W, H, H // 2, RED), tags="bg")
                    c.tag_lower("bg")
                elif SYSTEM == "Windows":
                    KEY = "#FF00FE"
                    b.configure(bg=KEY)
                    b.attributes("-transparentcolor", KEY)
                    c.configure(bg=KEY)
                    c.create_image(0, 0, anchor="nw", image=shape_img(W, H, H // 2, RED), tags="bg")
                    c.tag_lower("bg")
            except tk.TclError:
                pass
            self.banner_chat.configure(bg=RED)
            self.ctrl_banner = b

        def _banner_count(self, n):
            try:
                if getattr(self, "ctrl_banner", None) is not None:
                    self.banner_chat.configure(text=tr("แชท") + (" (%d)" % n if n else ""))
            except tk.TclError:
                pass

        def _hide_control_banner(self):
            b = getattr(self, "ctrl_banner", None)
            self.ctrl_banner = None
            if b is not None:
                try:
                    b.destroy()
                except tk.TclError:
                    pass

        def show_host_chat(self, show=True):
            if not self.host_chat:
                return
            w, panel = self.host_chat
            try:
                if show:
                    w.deiconify()
                    w.lift()
                    w.attributes("-topmost", True)
                    w.after(300, lambda: w.attributes("-topmost", False))
                    panel.seen()
                    self._banner_count(0)
                else:
                    w.withdraw()
            except tk.TclError:
                pass

        def _close_host_chat(self):
            self._hide_control_banner()
            if self.host_chat:
                try:
                    self.host_chat[0].destroy()
                except tk.TclError:
                    pass
            self.host_chat = None
            self.host_chat_btn.pack_forget()

        def _host_chat_event(self, ev):
            if not self.host_chat:
                return
            w, panel = self.host_chat
            try:
                visible = w.state() == "normal"
            except tk.TclError:
                return
            panel.on_event(ev, visible)

        def _ask_threadsafe(self, ip, name):
            ev, box = threading.Event(), {}
            self.q.put(("ask_accept", ip, name, ev, box))
            ev.wait(55)
            return bool(box.get("ok"))

        # ---------------- event loop ----------------
        def _poll(self):
            try:
                while True:
                    m = self.q.get_nowait()
                    k = m[0]
                    if k == "connected":
                        _, rid, tls, info, fp = m
                        self.conn_btn.configure(state="normal")
                        self.cstatus.set("")
                        rec = [rid] + [h for h in (parse_id(x) for x in self.cfg.get("recent", [])) if h and h != rid]
                        old = self._recent(rid) or {}
                        ri = [{"id": rid, "name": info.get("name", ""), "alias": old.get("alias", ""),
                               "t": time.time()}] + [r for r in self.cfg.get("recent_info", []) if r.get("id") != rid]
                        self.cfg.update({"recent": rec[:15], "recent_info": ri[:30]})
                        save_config(self.cfg)
                        self.host_cb.configure(values=[fmt_id(x) for x in rec[:15]])
                        self._refresh_recent(select=rid)
                        if old.get("alias"):
                            info = dict(info, name=old["alias"])
                        self.viewers.append(Viewer(self, tls, info, "ID " + fmt_id(rid), fp))
                    elif k == "connect_err":
                        self.conn_btn.configure(state="normal")
                        self.cstatus.set(m[1])
                    elif k == "viewer_closed":
                        v, reason = m[1], m[2]
                        if v in self.viewers:
                            self.viewers.remove(v)
                        if not v.closed:
                            v.destroy()
                            messagebox.showinfo(APP, tr("การเชื่อมต่อกับ %s สิ้นสุด\n%s") % (v.host, reason))
                    elif k == "relay_status":
                        self.relay_state["mon"], self.relay_state["data"] = m[1], m[2]
                        if m[1] in ("ok", "error", "unset"):
                            self.relay_state["t"] = time.time()
                        self._render_relay()
                    elif k == "ask_fp":
                        _, host, old, fp, name, ev, box = m
                        box["ok"] = messagebox.askyesno(
                            APP, tr("⚠ ข้อมูลยืนยันตัวตนของ %s (%s) เปลี่ยนไปจากที่เคยเชื่อมต่อ\n\nถ้าเครื่องปลายทางเพิ่งติดตั้งโปรแกรมใหม่ ถือว่าปกติ\nถ้าไม่ใช่ อาจมีผู้ไม่หวังดีพยายามดักข้อมูล\n\nต้องการเชื่อมต่อต่อหรือไม่?")
                                 % (name, host), icon="warning", default="no")
                        ev.set()
                    elif k == "ask_accept":
                        _, ip, name, ev, box = m
                        self.root.deiconify()
                        self.root.lift()
                        self.root.attributes("-topmost", True)
                        box["ok"] = messagebox.askyesno(
                            APP, (tr("%s (%s)\nขอเชื่อมต่อเพื่อควบคุมเครื่องนี้\n\nอนุญาตหรือไม่?") if self.allow_var.get()
                                  else tr("%s (%s)\nขอเชื่อมต่อเพื่อดูหน้าจอเครื่องนี้\n\nอนุญาตหรือไม่?")) % (name, ip),
                            parent=self.root)
                        self.root.attributes("-topmost", False)
                        ev.set()
                    elif k == "log":
                        self._log(m[1])
                    elif k == "session":
                        self._banner("busy", "%s (%s)" % (m[2], m[1]))
                    elif k == "relay":
                        self._update_id_row(m[1], m[2])
                        if m[1] == "error":
                            self._log(m[2])
                    elif k == "update_info":
                        self._on_update_info(m[1], m[2])
                    elif k == "update_progress":
                        self.upd_progress.configure(value=100.0 * m[1] / max(1, m[2]))
                        self.upd_status.configure(text=tr("กำลังดาวน์โหลด… %s / %s") % (fmt_size(m[1]), fmt_size(m[2])),
                                                  fg=T.c("muted"))
                    elif k == "update_done":
                        self._on_update_done(m[1])
                    elif k == "relay_test":
                        self.relay_test_var.set(m[1])
                    elif k == "latency":
                        if getattr(self, "session_who", None) and self.server and self.server.session:
                            word, _c = latency_style(m[2])
                            self._banner("busy", self.session_who, tr("โดย %s   ·   Latency %.0f ms (%s)")
                                         % (self.session_who, m[2], word))
                    elif k == "chat_open":
                        self._open_host_chat(m[1], m[2], m[3])
                    elif k == "chat":
                        self._host_chat_event(m[1])
                    elif k == "chat_end":
                        self._close_host_chat()
                    elif k == "session_end":
                        self.session_who = None
                        self._banner("wait" if self.server and self.server.is_alive() else "off")
                    elif k == "server_err":
                        self._log(m[1])
                        messagebox.showerror(APP, m[1])
                        self.server = None
                        self.srv_btn.configure(text=tr("▶  เริ่มเปิดรับการเชื่อมต่อ"))
                        self._banner("off")
                        self._update_id_row()
            except queue.Empty:
                pass
            self.root.after(50, self._poll)

        def quit(self, installing=False):
            if self.update_ready and not installing:          # ติดตั้งอัปเดตที่ดาวน์โหลดไว้ตอนปิดโปรแกรม
                try:
                    launch_installer(self.update_ready, relaunch=False)
                except Exception:
                    pass
            for v in list(self.viewers):
                v.disconnect()
            if self.server:
                self.server.stop()
            self.root.after(200, self.root.destroy)

    if env_bool("DIRECT_CONNECT", True):
        UPNP.start()
    root = tk.Tk()
    T = Theme(root, env_str("THEME", load_config().get("theme", "auto")))
    set_app_icon(root)
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.quit)
    if SYSTEM == "Darwin":
        try:
            root.createcommand("tk::mac::Quit", app.quit)
        except Exception:
            pass
    root.mainloop()
    if RESTART:                                         # เปลี่ยนภาษา → เปิดโปรแกรมใหม่
        if getattr(sys, "frozen", False):
            cmd = [sys.executable] + sys.argv[1:]
        else:
            cmd = [sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:]
        relaunch_self(cmd)


# ============================================================================
# โหมดไม่มีหน้าต่าง
# ============================================================================
def run_headless_server(args):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    cfg = load_config()
    pw = args.password or env_str("HOST_PASSWORD") or cfg.get("password") or gen_password()
    cfg.update({"password": pw})
    addr = args.relay or env_str("RELAY_ADDR") or cfg.get("relay_addr", "")
    key = args.relay_key if args.relay_key is not None else (ENV.get("RELAY_KEY", "") if env_str("RELAY_ADDR")
                                                            else cfg.get("relay_key", ""))
    if not addr:
        print(tr("ต้องระบุ Relay Server: --relay HOST:PORT หรือใส่ RELAY_ADDR ในไฟล์ .env"))
        return 1
    if not cfg.get("host_id") or not cfg.get("host_secret"):
        cfg.update({"host_id": new_host_id(), "host_secret": secrets.token_hex(24)})
    save_config(cfg)
    q = queue.Queue()
    relay = {"addr": addr, "key": key, "id": cfg["host_id"], "secret": cfg["host_secret"],
             "direct": env_bool("DIRECT_CONNECT", True), "direct_port": direct_port()}
    srv = Server(0, pw, q, None, not args.view_only, not args.no_files, relay=relay)
    srv.ui = False
    print(tr("%s %s — เปิดรับการเชื่อมต่อผ่าน Relay") % (APP, VERSION))
    print("  ID       : %s" % fmt_id(relay["id"]))
    print(tr("  รหัสผ่าน : %s") % pw)
    print("  Relay    : %s" % addr)
    print("  Cert     : %s" % srv.fp[:47])
    if ENV_PATH:
        print("  .env     : %s" % ENV_PATH)
    print(tr("กด Ctrl+C เพื่อหยุด\n"))
    srv.start()
    try:
        while srv.is_alive():
            try:
                m = q.get(timeout=0.5)
            except queue.Empty:
                continue
            stamp = datetime.now().strftime("%H:%M:%S")
            if m[0] in ("log", "server_err"):
                print(stamp, m[1])
            elif m[0] == "relay" and m[1] in ("online", "error"):
                print(stamp, m[2])
            elif m[0] == "chat" and m[1].get("ev") == "msg" and not m[1].get("mine"):
                print(stamp, "💬 %s: %s" % (m[1].get("name", ""), m[1].get("text", "")))
            elif m[0] == "chat" and m[1].get("ev") == "progress" and m[1].get("status") == "received":
                print(stamp, "📎 %s" % m[1].get("path", ""))
    except KeyboardInterrupt:
        srv.stop()
        print(tr("\nหยุดแล้ว"))
    return 0


def main():
    threading.Thread(target=cleanup_old_exe, daemon=True).start()
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 4096 if hard == resource.RLIM_INFINITY else min(4096, hard)
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    except Exception:
        pass
    p = argparse.ArgumentParser(description=tr("NetRemote — Remote Desktop ผ่าน Relay"))
    p.add_argument("--server", action="store_true", help=tr("เปิดรับการเชื่อมต่อแบบไม่มีหน้าต่าง"))
    p.add_argument("--password", help=tr("รหัสผ่าน (โหมด --server)"))
    p.add_argument("--view-only", action="store_true", help=tr("ให้ดูหน้าจออย่างเดียว (โหมด --server)"))
    p.add_argument("--no-files", action="store_true", help=tr("ไม่อนุญาตรับ-ส่งไฟล์ (โหมด --server)"))
    p.add_argument("--relay", help=tr("Relay Server เช่น relay.example.com:5910 (หรือ RELAY_ADDR ใน .env)"))
    p.add_argument("--relay-key", help="Relay Key")
    args = p.parse_args()
    if args.server:
        miss = missing_modules(server=True)
        if miss:
            print(tr("ยังไม่ได้ติดตั้ง: pip install ") + " ".join(miss))
            return 1
        return run_headless_server(args)
    miss = missing_modules(server=False)
    if miss:
        print(tr("ยังไม่ได้ติดตั้ง: pip install ") + " ".join(miss))
        return 1
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
