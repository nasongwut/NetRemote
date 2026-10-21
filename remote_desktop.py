#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRemote — โปรแกรม Remote Desktop สำหรับวง LAN
================================================
ดูหน้าจอ + ควบคุมเมาส์/คีย์บอร์ดของอีกเครื่องผ่านเครือข่าย
- เข้ารหัสทั้งหมดด้วย TLS (สร้าง Certificate ให้เองอัตโนมัติ)
- ยืนยันตัวตนด้วยรหัสผ่าน (HMAC ผูกกับ Certificate ป้องกันการดักกลางทาง)
- ส่งเฉพาะส่วนของหน้าจอที่เปลี่ยน (ประหยัดเน็ต)
- รองรับหลายจอ, ปรับคุณภาพภาพ, โหมดดูอย่างเดียว, ถามก่อนรับการเชื่อมต่อ
- ค้นหาเครื่องที่เปิดรับการเชื่อมต่อในวง LAN

ต้องติดตั้ง:  pip install mss Pillow pynput cryptography
(ไฟล์ "Remote Desktop.command" จะติดตั้งให้อัตโนมัติในครั้งแรก)

ใช้งาน:
    python3 remote_desktop.py                         เปิดหน้าต่างโปรแกรม
    python3 remote_desktop.py --server [--password X] เปิดรับการเชื่อมต่อแบบไม่มีหน้าต่าง
"""
import argparse
import base64
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
VERSION = "1.0"
PROTO = 1
DEFAULT_PORT = 5905
SYSTEM = platform.system()
CONF_DIR = os.path.join(os.path.expanduser("~"), ".netremote")
CONF_FILE = os.path.join(CONF_DIR, "config.json")
CERT_FILE = os.path.join(CONF_DIR, "cert.pem")
KEY_FILE = os.path.join(CONF_DIR, "key.pem")

T_HELLO, T_AUTH, T_OK, T_ERR = 1, 2, 3, 4
T_REQ, T_FRAME, T_INPUT, T_BYE = 10, 11, 20, 40
T_PING, T_PONG = 30, 31


def latency_style(ms):
    """คืน (ข้อความ, สี) ตามระดับ Latency"""
    if ms is None:
        return "—", "#888888"
    if ms < 30:
        return "ดีมาก", "#1f9d55"
    if ms < 80:
        return "ดี", "#1f9d55"
    if ms < 150:
        return "พอใช้", "#d97706"
    return "ช้า", "#dc2626"
HDR = struct.Struct("!BI")
MAX_MSG = 64 * 1024 * 1024

# คุณภาพภาพ: (ชื่อ, ความกว้างสูงสุด 0=เต็ม, JPEG quality, subsampling)
QUALITY = [("ประหยัด", 1280, 45, 2), ("ปกติ", 1600, 60, 2), ("คมชัด", 1920, 75, 1), ("สูงสุด", 0, 88, 0)]

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
            raise ConnectionError("การเชื่อมต่อถูกปิด")
        buf += chunk
    return bytes(buf)


def recv_msg(sock):
    t, n = HDR.unpack(recv_exact(sock, HDR.size))
    if n > MAX_MSG:
        raise ConnectionError("ข้อมูลผิดรูปแบบ")
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
            raise RuntimeError("สร้าง Certificate ไม่ได้ — ติดตั้ง: pip install cryptography")
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

    def send(self, t, payload=b""):
        if not self.alive:
            return False
        with self.lock:
            self.out.append(HDR.pack(t, len(payload)) + payload)
        self._wake()
        return True

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
                                self.reason = self.reason or "อีกฝั่งปิดการเชื่อมต่อ"
                                raise ConnectionError(self.reason)
                            rbuf += data
                            self.bytes_in += len(data)
                            self.last_rx = time.time()
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError, InterruptedError):
                        pass
                    while len(rbuf) >= HDR.size:
                        t, n = HDR.unpack_from(rbuf, 0)
                        if n > MAX_MSG:
                            raise ConnectionError("ข้อมูลผิดรูปแบบ")
                        if len(rbuf) < HDR.size + n:
                            break
                        payload = bytes(rbuf[HDR.size:HDR.size + n])
                        del rbuf[:HDR.size + n]
                        if t == T_BYE:
                            self.reason = self.reason or "อีกฝั่งตัดการเชื่อมต่อ"
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
                    except (ssl.SSLWantWriteError, ssl.SSLWantReadError, BlockingIOError, InterruptedError):
                        pass
                if self.idle and time.time() - self.last_rx > self.idle:
                    self.reason = self.reason or "ไม่ได้รับข้อมูลนานเกินไป (หมดเวลา)"
                    break
        except Exception as e:
            self.reason = self.reason or str(e) or e.__class__.__name__
        finally:
            self.alive = False
            if self.reason in ("", None):
                self.reason = "ตัดการเชื่อมต่อแล้ว"
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
            s["chan"].close("เครื่องปลายทางตัดการเชื่อมต่อ")

    def run(self):
        if self.relay:
            r = self.relay
            self.relay_thread = RelayHost(self, r["addr"], r.get("key", ""), r["id"], r["secret"], self.events)
            self.relay_thread.start()
        try:
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind(("0.0.0.0", self.port))
            ls.listen(8)
            ls.settimeout(1.0)
            self.lsock = ls
        except OSError as e:
            if self.relay_thread:
                self.log("⚠ เปิดพอร์ต LAN %d ไม่ได้ (%s) — รับการเชื่อมต่อผ่าน Relay อย่างเดียว"
                         % (self.port, e.strerror or e))
                self.stop_event.wait()
                return
            self.events.put(("server_err", "เปิดพอร์ต %d ไม่ได้: %s" % (self.port, e.strerror or e)))
            return
        self.log("เปิดรับการเชื่อมต่อที่พอร์ต %d" % self.port)
        while not self.stop_event.is_set():
            try:
                conn, addr = ls.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._client, args=(conn, addr), daemon=True).start()
        self.log("ปิดการรับการเชื่อมต่อแล้ว")

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
                raise ConnectionError("protocol")
            auth = jload(p)
            name = str(auth.get("name", ip))[:60]
            if not hmac.compare_digest(str(auth.get("mac", "")), auth_mac(self.password, nonce, self.fp)):
                cnt += 1
                self.fails[ip] = (cnt, time.time() + (60 if cnt >= 3 else 0))
                time.sleep(1.0)
                send_msg(tls, T_ERR, jdump({"msg": "รหัสผ่านไม่ถูกต้อง"}))
                self.log("⚠ %s (%s) ใส่รหัสผ่านผิด%s" % (name, ip, " — บล็อก 60 วินาที" if cnt >= 3 else ""))
                tls.close()
                return
            self.fails.pop(ip, None)
            with self.session_lock:
                busy = self.session is not None
            if busy:
                send_msg(tls, T_ERR, jdump({"msg": "เครื่องนี้มีผู้เชื่อมต่ออยู่แล้ว"}))
                tls.close()
                return
            if self.ask_cb:
                self.log("%s (%s) ขอเชื่อมต่อ — รอการยืนยัน" % (name, ip))
                tls.settimeout(60)
                if not self.ask_cb(ip, name):
                    send_msg(tls, T_ERR, jdump({"msg": "เครื่องปลายทางปฏิเสธการเชื่อมต่อ"}))
                    self.log("ปฏิเสธการเชื่อมต่อจาก %s (%s)" % (name, ip))
                    tls.close()
                    return
            with self.session_lock:
                if self.session is not None:
                    send_msg(tls, T_ERR, jdump({"msg": "เครื่องนี้มีผู้เชื่อมต่ออยู่แล้ว"}))
                    tls.close()
                    return
                self.session = {"ip": ip, "name": name}
        except Exception as e:
            try:
                tls.close()
            except Exception:
                pass
            if not isinstance(e, (ConnectionError, socket.timeout, ssl.SSLError)):
                self.log("ผิดพลาด: %s" % e)
            return

        cap = inj = None
        try:
            cap = Capturer()
            try:
                inj = Injector()
            except Exception as e:
                self.log("⚠ ควบคุมเมาส์/คีย์บอร์ดไม่ได้: %s" % e)
            mons = [{"w": m["width"], "h": m["height"]} for m in cap.monitors]
            send_msg(tls, T_OK, jdump({"name": computer_name(), "os": SYSTEM, "monitors": mons,
                                       "files": bool(self.allow_files), "v": PROTO,
                                       "control": bool(self.allow_control and inj)}))
            self._session_loop(tls, ip, name, cap, inj)
        except Exception as e:
            self.log("ผิดพลาดระหว่างเชื่อมต่อ: %s" % e)
            try:
                send_msg(tls, T_ERR, jdump({"msg": "เครื่องปลายทางผิดพลาด: %s" % e}))
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
        self.session["chan"] = chan
        chan.start()
        self.events.put(("session", ip, name))
        self.log("● %s (%s) เชื่อมต่อแล้ว" % (name, ip))
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
        chan.close("เครื่องนี้ตัดการเชื่อมต่อ" if self.stop_event.is_set() else "")
        chan.join(3)
        self.events.put(("session_end", ip, reason["r"] or chan.reason))
        self.log("○ %s (%s) ออกจากการเชื่อมต่อ — %s" % (name, ip, reason["r"] or chan.reason))

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
            self.log("ควบคุมไม่สำเร็จ: %s" % e)


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
        return "ไม่มีสิทธิ์เข้าถึง"
    if isinstance(e, FileNotFoundError):
        return "ไม่พบไฟล์หรือโฟลเดอร์"
    if isinstance(e, FileExistsError):
        return "มีชื่อนี้อยู่แล้ว"
    if isinstance(e, OSError) and e.strerror:
        return e.strerror
    return str(e) or e.__class__.__name__


def safe_parts(rel):
    parts = [p for p in re.split(r"[\\/]+", str(rel)) if p not in ("", ".")]
    if not parts or any(p == ".." or ":" in p or "\0" in p for p in parts):
        raise ValueError("ชื่อไฟล์ไม่ถูกต้อง: %s" % rel)
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
            err = "เครื่องปลายทางไม่อนุญาตให้รับ-ส่งไฟล์"
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
            if d.get("op") == "mkdir":
                parts = safe_parts(d.get("name", ""))
                if len(parts) != 1:
                    raise ValueError("ชื่อโฟลเดอร์ไม่ถูกต้อง")
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
                raise ValueError("ไม่พบโฟลเดอร์ปลายทาง")
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
            self._send(T_XDONE, {"tid": tid, "ok": False, "err": "ไม่พบการอัปโหลดนี้"})
            return
        try:
            st["f"].close()
            st["f"] = None
            os.replace(st["tmp"], st["final"])
            st["count"] += 1
            self._send(T_XDONE, {"tid": tid, "ok": True, "path": st["final"]})
            self.log("⬆ ได้รับไฟล์ %s (%s) จาก %s" % (os.path.basename(st["final"]),
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
                self.log("⬇ ส่งไฟล์ %d ไฟล์ (%s) ให้ %s" % (len(files), fmt_size(total), self.who))
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
               "acked": 0, "count": 0, "idx": 0, "status": "กำลังเริ่ม…", "state": "active",
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
        return name + (" และอีก %d รายการ" % (len(paths) - 1) if len(paths) > 1 else "")

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
            raise ConnectionError("ปลายทางไม่ตอบสนอง")
        if not r.get("ok"):
            raise ConnectionError(r.get("err") or "ผิดพลาด")
        return r

    def _upload_worker(self, job, local_paths):
        tid = job["tid"]
        sent = 0
        try:
            files = expand_paths(local_paths)
            if not files:
                raise ValueError("ไม่มีไฟล์ให้ส่ง")
            job.update(total=sum(s for _, _, s in files), count=len(files))
            for i, (lp, rel, size) in enumerate(files):
                job.update(idx=i + 1, status="กำลังส่ง %d/%d  %s" % (i + 1, len(files), rel))
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
                            raise ConnectionError("การเชื่อมต่อถูกตัด")
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
        job["status"] = "กำลังเตรียมไฟล์…"
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
                       status="กำลังรับ %d/%d  %s" % (int(d.get("idx", 0)) + 1, int(d.get("count", 0)),
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
                    job["failed"] = d.get("err") or "ผิดพลาด"
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
                    self._finish(job, False, d.get("err") or "ผิดพลาด")
                elif not d.get("count"):
                    self._finish(job, False, "ไม่มีไฟล์ (โฟลเดอร์ว่าง)")
                else:
                    job["total"] = int(d.get("total", job["total"]))
                    self._finish(job, True)

    def _finish(self, job, ok, err=""):
        if job["state"] != "active":
            return
        job["t1"] = time.time()
        if ok:
            job["state"] = "done"
            job["status"] = "✓ เสร็จ (%d ไฟล์)" % len(job["files"])
        else:
            job["state"] = "cancelled" if job["cancel"] else "error"
            job["status"] = ("ยกเลิกแล้ว" if job["cancel"] and not err else "✗ " + err)
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
                self._finish(job, False, "การเชื่อมต่อถูกตัด")


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
        raise ValueError("ยังไม่ได้ตั้งค่า Relay Server")
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
            raise ConnectionError("Relay ปิดการเชื่อมต่อ")
        if b == b"\n":
            return json.loads(buf.decode("utf-8"))
        buf += b
        if len(buf) > limit:
            raise ConnectionError("ข้อมูลจาก Relay ผิดรูปแบบ")


def _relay_socket(addr, timeout=10):
    h, p = parse_hostport(addr, RELAY_PORT)
    s = socket.create_connection((h, p), timeout=timeout)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return s


def relay_dial(addr, key, host_id):
    """เครื่องที่ควบคุม: ขอเชื่อมต่อไปยัง ID ผ่าน Relay — คืน socket ที่ต่อตรงถึงปลายทาง"""
    s = _relay_socket(addr)
    try:
        s.settimeout(25)
        line_send(s, {"role": "client", "id": host_id, "key": key or "", "v": 1})
        r = line_recv(s)
        if not r.get("ok"):
            raise ConnectionError(r.get("err") or "Relay ปฏิเสธการเชื่อมต่อ")
        return s
    except Exception:
        s.close()
        raise


def relay_test(addr, key):
    s = _relay_socket(addr)
    try:
        s.settimeout(10)
        line_send(s, {"role": "ping", "key": key or "", "v": 1})
        r = line_recv(s)
        if not r.get("ok"):
            raise ConnectionError(r.get("err") or "Relay ปฏิเสธ")
        return r
    finally:
        s.close()


class RelayHost(threading.Thread):
    """เครื่องที่ถูกควบคุม: ลงทะเบียน ID กับ Relay และรอรับการเชื่อมต่อจากอินเทอร์เน็ต"""

    def __init__(self, server, addr, key, host_id, secret, events):
        super().__init__(daemon=True)
        self.server, self.addr, self.key = server, addr, key or ""
        self.host_id, self.secret, self.events = host_id, secret, events
        self.stop_event = threading.Event()
        self.sock = None

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
            self.status("connecting", "กำลังเชื่อมต่อ Relay %s …" % self.addr)
            wait = backoff
            try:
                s = _relay_socket(self.addr)
                self.sock = s
                s.settimeout(15)
                line_send(s, {"role": "host", "id": self.host_id, "secret": self.secret, "key": self.key,
                              "name": computer_name(), "v": 1})
                r = line_recv(s)
                if not r.get("ok"):
                    self.status("error", r.get("err") or "Relay ปฏิเสธ")
                    wait = 60
                    raise ConnectionError("")
                self.status("online", "ออนไลน์ผ่าน Relay %s" % self.addr)
                self.server.log("เชื่อมต่อ Relay %s แล้ว — ID %s" % (self.addr, fmt_id(self.host_id)))
                backoff = 3
                s.settimeout(1.0)
                buf, last_ping, last_rx = b"", time.time(), time.time()
                while not self.stop_event.is_set():
                    now = time.time()
                    if now - last_ping > 20:
                        line_send(s, {"cmd": "ping"})
                        last_ping = now
                    if now - last_rx > 70:
                        raise ConnectionError("Relay ไม่ตอบสนอง")
                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        raise ConnectionError("Relay ปิดการเชื่อมต่อ")
                    last_rx = time.time()
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        try:
                            msg = json.loads(line.decode("utf-8"))
                        except ValueError:
                            continue
                        if msg.get("cmd") == "connect":
                            threading.Thread(target=self._data, args=(msg.get("token", ""), msg.get("from", "?")),
                                             daemon=True).start()
            except Exception as e:
                if not self.stop_event.is_set() and str(e):
                    self.status("error", "Relay: %s" % err_text(e))
            finally:
                try:
                    self.sock.close()
                except Exception:
                    pass
            if self.stop_event.wait(wait):
                break
            backoff = min(backoff * 2, 60)
        self.status("off", "ปิดการเชื่อมต่อ Relay")

    def _data(self, token, from_ip):
        try:
            ds = _relay_socket(self.addr)
            line_send(ds, {"role": "data", "token": token, "v": 1})
        except Exception as e:
            self.server.log("เชื่อมต่อข้อมูลผ่าน Relay ไม่สำเร็จ: %s" % err_text(e))
            return
        self.server._client(ds, ("%s (ผ่านอินเทอร์เน็ต)" % from_ip, 0))


# ============================================================================
# ฝั่งเครื่องที่ควบคุม (Client)
# ============================================================================
def client_connect(host, port, password, confirm_fp, relay=None):
    """เชื่อมต่อ + ยืนยันตัวตน คืนค่า (tls_socket, info, fingerprint)
    confirm_fp(host, fp) -> bool  ใช้ตรวจ Certificate ของปลายทาง"""
    if relay:                                     # ผ่านอินเทอร์เน็ต: ต่อผ่าน Relay ด้วย ID
        raw = relay_dial(relay["addr"], relay.get("key", ""), relay["id"])
    else:
        raw = socket.create_connection((host, port), timeout=8)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        tls = client_context().wrap_socket(raw)
    except Exception:
        raw.close()
        raise ConnectionError("เชื่อมต่อแบบเข้ารหัสไม่ได้ — ปลายทางอาจไม่ใช่ NetRemote")
    try:
        fp = fingerprint(tls.getpeercert(binary_form=True))
        t, p = recv_msg(tls)
        hello = jload(p) if t == T_HELLO else {}
        if hello.get("app") != APP:
            raise ConnectionError("ปลายทางไม่ใช่ NetRemote")
        if not confirm_fp(host, fp, hello.get("name", "")):
            raise ConnectionError("ยกเลิก — Certificate ของปลายทางไม่ตรงกับที่เคยบันทึกไว้")
        nonce = base64.b64decode(hello["nonce"])
        send_msg(tls, T_AUTH, jdump({"mac": auth_mac(password, nonce, fp), "name": computer_name(),
                                     "os": SYSTEM}))
        tls.settimeout(70)                          # ปลายทางอาจต้องกดยืนยัน
        t, p = recv_msg(tls)
        if t == T_ERR:
            raise ConnectionError(jload(p).get("msg", "ถูกปฏิเสธ"))
        if t != T_OK:
            raise ConnectionError("protocol")
        info = jload(p)
        tls.settimeout(None)
        return tls, info, fp
    except Exception:
        try:
            tls.close()
        except Exception:
            pass
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
            bar = T.track(tk.Frame(win, bd=0), bg="card")
            bar.pack(fill="x")
            inner = box(bar)
            inner.pack(fill="x", padx=12, pady=8)
            mons = info.get("monitors") or [{"w": 0, "h": 0}]
            self.mon_var = tk.StringVar()
            mvals = ["จอ %d (%d×%d)" % (i + 1, m["w"], m["h"]) for i, m in enumerate(mons)]
            lbl(inner, "●", fg="ok", font="h2").pack(side="left")
            lbl(inner, info.get("name", host)[:18], font="bold").pack(side="left", padx=(6, 12))
            if len(mons) > 1:
                cb = ttk.Combobox(inner, values=mvals, textvariable=self.mon_var, state="readonly", width=15)
                cb.current(0)
                cb.pack(side="left", padx=(0, 8))
                cb.bind("<<ComboboxSelected>>", lambda e: self.request(full=True))
            else:
                self.mon_var.set(mvals[0])
            self.mvals = mvals
            self.q_var = tk.StringVar(value=app.cfg.get("quality", "ปกติ"))
            qb = ttk.Combobox(inner, values=[q[0] for q in QUALITY], textvariable=self.q_var,
                              state="readonly", width=8)
            qb.pack(side="left", padx=(0, 12))
            qb.bind("<<ComboboxSelected>>", lambda e: self._quality_changed())
            self.ctrl_var = tk.BooleanVar(value=self.can_control and not app.view_only_var.get())
            cbx = ttk.Checkbutton(inner, text="ควบคุม", variable=self.ctrl_var, style="Card.TCheckbutton",
                                  command=self._release_all)
            cbx.pack(side="left")
            if not self.can_control:
                cbx.configure(state="disabled")
            remote_mac = info.get("os") == "Darwin"
            self.swap_var = tk.BooleanVar(value=(SYSTEM == "Darwin") != remote_mac)
            ttk.Checkbutton(inner, text="สลับ ⌘↔Ctrl", variable=self.swap_var,
                            style="Card.TCheckbutton").pack(side="left", padx=(10, 0))
            ttk.Button(inner, text="ตัดการเชื่อมต่อ", style="Tool.Danger.TButton",
                       command=self.disconnect).pack(side="right")
            ttk.Button(inner, text="⛶ เต็มจอ", style="Tool.TButton", command=self.toggle_full).pack(side="right", padx=(0, 5))
            ttk.Button(inner, text="⟲ ปล่อยปุ่ม", style="Tool.TButton",
                       command=self._release_all).pack(side="right", padx=(0, 5))
            ttk.Button(inner, text="✎ ข้อความ", style="Tool.TButton", command=self.send_text).pack(side="right", padx=(0, 5))
            ttk.Button(inner, text="📁 ไฟล์", style="Tool.Accent.TButton",
                       command=self.open_files).pack(side="right", padx=(0, 5))
            self.lat_lbl = lbl(inner, "Latency —", fg="muted", bg="subtle", font="smallbold", padx=10, pady=4)
            self.lat_lbl.pack(side="right", padx=(0, 12))
            self.rtt = self.rtt_avg = self.rtt_min = self.rtt_max = None
            self.last_pong = time.time()
            T.track(tk.Frame(win, height=1, bd=0), bg="border").pack(fill="x")

            self.canvas = T.track(tk.Canvas(win, highlightthickness=0, cursor="arrow"), bg="viewer")
            self.canvas.pack(fill="both", expand=True)
            self.img_item = self.canvas.create_image(0, 0, anchor="nw")
            self.cur_item = self.canvas.create_polygon(0, 0, 0, 0, fill="white", outline="black", width=1)
            self.wait_item = self.canvas.create_text(300, 200, text="กำลังรับภาพหน้าจอ…", fill="#9AA3B2",
                                                     font=T.f["h2"])

            st = box(win, bg="bg")
            st.pack(fill="x")
            self.status = tk.StringVar(value="เชื่อมต่อแล้ว")
            lbl(st, textvariable=self.status, fg="muted", bg="bg", font="small").pack(side="left", padx=12, pady=5)
            lbl(st, "🔒 TLS  %s" % fp[:23], fg="muted", bg="bg", font="small").pack(side="right", padx=12)

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
            self.chan.start()
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
                self.lat_lbl.configure(text="●  ไม่ตอบสนอง", fg=T.c("danger"), bg=T.c("danger_bg"))
            elif self.rtt_avg is not None:
                word, _c = latency_style(self.rtt_avg)
                lv = "ok" if self.rtt_avg < 80 else ("warn" if self.rtt_avg < 150 else "danger")
                self.lat_lbl.configure(text="●  %.0f ms · %s" % (self.rtt_avg, word),
                                       fg=T.c(lv), bg=T.c(lv + "_bg"))
            self.win.after(1000, self._ping_loop)

        def _stats_loop(self):
            if self.closed:
                return
            now = time.time()
            dt = now - self.stats["t0"]
            fps = self.stats["frames"] / dt if dt else 0
            kbs = (self.chan.bytes_in - self.stats["b0"]) / 1024 / dt if dt else 0
            self.stats.update({"frames": 0, "t0": now, "b0": self.chan.bytes_in})
            mode = "ควบคุมได้" if self.ctrl_var.get() else "ดูอย่างเดียว"
            lat = ("  ·  Latency ต่ำสุด %.0f / สูงสุด %.0f ms" % (self.rtt_min, self.rtt_max)
                   if self.rtt_min is not None else "")
            self.status.set("เชื่อมต่อกับ %s (%s)  ·  %s  ·  %.0f ภาพ/วิ  ·  %s KB/s%s"
                            % (self.info.get("name", ""), self.host, mode, fps, format(int(kbs), ","), lat))
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
                messagebox.showinfo(APP, "เปิด \"ควบคุมเมาส์/คีย์บอร์ด\" ก่อน", parent=self.win)
                return
            s = simpledialog.askstring(APP, "พิมพ์ข้อความที่จะส่งไปพิมพ์บนเครื่องปลายทาง\n"
                                            "(รองรับภาษาไทย — คลิกช่องที่ต้องการพิมพ์บนเครื่องปลายทางไว้ก่อน)",
                                       parent=self.win)
            if s:
                self._input({"t": "type", "s": s})

        def toggle_full(self):
            full = not bool(self.win.attributes("-fullscreen"))
            self.win.attributes("-fullscreen", full)

        def disconnect(self):
            if not self.closed:
                self.chan.close("ตัดการเชื่อมต่อแล้ว")
                self.destroy()

        def open_files(self):
            if not self.info.get("files"):
                if "v" not in self.info:
                    msg = ("เครื่องปลายทาง (%s) ใช้โปรแกรม NetRemote เวอร์ชันเก่า ที่ยังไม่รองรับการรับ-ส่งไฟล์\n\n"
                           "ให้อัปเดตโปรแกรมบนเครื่องปลายทางเป็นเวอร์ชันล่าสุด แล้วเชื่อมต่อใหม่" % self.info.get("name", ""))
                else:
                    msg = ("เครื่องปลายทาง (%s) ปิดการรับ-ส่งไฟล์ไว้\n\n"
                           "ที่เครื่องปลายทาง: แท็บ \"ให้เครื่องอื่นควบคุมเครื่องนี้\" → ติ๊ก \"อนุญาตให้รับ-ส่งไฟล์\" "
                           "แล้วเชื่อมต่อใหม่" % self.info.get("name", ""))
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
            ttk.Button(nav, text="⬆ ขึ้น", width=6, command=self.up).pack(side="left")
            home = os.path.expanduser("~")
            for label, sub in (("⌂ Home", ""), ("Desktop", "Desktop"), ("Documents", "Documents"),
                               ("Downloads", "Downloads")):
                p = os.path.join(home, sub) if sub else home
                if os.path.isdir(p):
                    ttk.Button(nav, text=label, command=lambda p=p: self.go(p)).pack(side="left", padx=(4, 0))
            if SYSTEM == "Darwin" and os.path.isdir("/Volumes"):
                ttk.Button(nav, text="ไดรฟ์", command=lambda: self.go("/Volumes")).pack(side="left", padx=(4, 0))
            self.path_var = tk.StringVar()
            pe = ttk.Entry(w, textvariable=self.path_var)
            pe.pack(fill="x", padx=10, pady=(2, 4))
            pe.bind("<Return>", lambda e: self.go(self.path_var.get().strip()))
            hint = ("เลือกได้หลายรายการ (กด ⌘/Ctrl หรือ Shift ค้าง) — เลือกโฟลเดอร์ได้ด้วย ดับเบิลคลิกโฟลเดอร์เพื่อเปิด"
                    if mode == "files" else "เปิดโฟลเดอร์ที่ต้องการ แล้วกด \"เลือกโฟลเดอร์นี้\" (หรือคลิกเลือกโฟลเดอร์ย่อย)")
            ttk.Label(w, text=hint, style="Muted.TLabel", padding=(10, 0)).pack(fill="x")
            fr = ttk.Frame(w, padding=(10, 4, 10, 0))
            fr.pack(fill="both", expand=True)
            t = self.tree = ttk.Treeview(fr, columns=("name", "size", "mtime"), show="headings",
                                         selectmode="extended" if mode == "files" else "browse")
            for c, txt, wd, st in (("name", "ชื่อ", 400, True), ("size", "ขนาด", 100, False),
                                   ("mtime", "แก้ไขล่าสุด", 150, False)):
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
            ttk.Button(bot, text="ยกเลิก", command=w.destroy).pack(side="right")
            ttk.Button(bot, text="เลือก" if mode == "files" else "เลือกโฟลเดอร์นี้", style="Accent.TButton",
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
                messagebox.showerror(APP, "เปิดโฟลเดอร์ไม่ได้: %s" % err_text(e), parent=self.win)
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
                self.info_var.set("เลือก %d รายการ" % len(sel))
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
                    messagebox.showinfo(APP, "คลิกเลือกไฟล์หรือโฟลเดอร์ก่อน", parent=self.win)
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
    class FileWindow:
        """หน้าต่างรับ-ส่งไฟล์: เรียกดูไฟล์เครื่องปลายทาง / อัปโหลด / ดาวน์โหลด"""

        def __init__(self, viewer):
            self.v, self.fc, self.app = viewer, viewer.files, viewer.app
            self.cur_path = None
            self.parent_path = None
            self.pending = None
            self.entries = {}
            self.speed = {}
            w = self.win = T.track(tk.Toplevel(viewer.win), bg="bg")
            w.title("รับ-ส่งไฟล์ — %s" % viewer.info.get("name", viewer.host))
            w.geometry("900x660")
            w.minsize(640, 480)
            w.protocol("WM_DELETE_WINDOW", w.withdraw)

            nav = ttk.Frame(w, padding=(10, 10, 10, 4))
            nav.pack(fill="x")
            ttk.Button(nav, text="⬆ ขึ้น", width=6, command=self.go_up).pack(side="left")
            ttk.Button(nav, text="⌂ Home", width=7, command=lambda: self.go(None)).pack(side="left", padx=4)
            ttk.Button(nav, text="⟳", width=3, command=self.refresh).pack(side="left")
            self.path_var = tk.StringVar()
            pe = ttk.Entry(nav, textvariable=self.path_var)
            pe.pack(side="left", fill="x", expand=True, padx=6)
            pe.bind("<Return>", lambda e: self.go(self.path_var.get().strip() or None))
            self.hidden_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(nav, text="แสดงไฟล์ซ่อน", variable=self.hidden_var, command=self.refresh).pack(side="left")

            ttk.Label(w, text="ไฟล์บนเครื่องปลายทาง — %s   (ดับเบิลคลิกโฟลเดอร์เพื่อเปิด, ดับเบิลคลิกไฟล์เพื่อดาวน์โหลด)"
                      % viewer.info.get("name", viewer.host), style="Muted.TLabel",
                      padding=(10, 2)).pack(fill="x")
            fr = ttk.Frame(w, padding=(10, 4, 10, 0))
            fr.pack(fill="both", expand=True)
            t = self.tree = ttk.Treeview(fr, columns=("name", "size", "mtime"), show="headings", selectmode="extended")
            for c, txt, wd, st in (("name", "ชื่อ", 420, True), ("size", "ขนาด", 100, False),
                                   ("mtime", "แก้ไขล่าสุด", 150, False)):
                t.heading(c, text=txt)
                t.column(c, width=wd, stretch=st, anchor="e" if c == "size" else "w")
            sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview)
            t.configure(yscrollcommand=sb.set)
            t.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            t.bind("<Double-1>", self.on_open)
            t.bind("<BackSpace>", lambda e: self.go_up())

            act = ttk.Frame(w, padding=(10, 6))
            act.pack(fill="x")
            ttk.Button(act, text="⬆ อัปโหลดไฟล์…", style="Accent.TButton", command=self.upload_files).pack(side="left")
            ttk.Button(act, text="⬆ อัปโหลดโฟลเดอร์…", command=self.upload_folder).pack(side="left", padx=6)
            ttk.Button(act, text="⬇ ดาวน์โหลดที่เลือก", style="Accent.TButton", command=self.download).pack(side="left")
            ttk.Button(act, text="+ สร้างโฟลเดอร์", command=self.mkdir).pack(side="left", padx=4)

            dl = ttk.Frame(w, padding=(10, 0, 10, 4))
            dl.pack(fill="x")
            ttk.Label(dl, text="บันทึกไฟล์ที่ดาวน์โหลดไว้ที่:").pack(side="left")
            self.dl_var = tk.StringVar(value=self._dl_dir())
            ttk.Label(dl, textvariable=self.dl_var, style="Link.TLabel").pack(side="left", padx=6)
            ttk.Button(dl, text="เปลี่ยน…", command=self.change_dl).pack(side="left")
            ttk.Button(dl, text="เปิดโฟลเดอร์", command=lambda: open_path(self.dl_var.get())).pack(side="left", padx=4)

            ttk.Label(w, text="การรับ-ส่งไฟล์", style="H2.TLabel", padding=(10, 8, 10, 4)).pack(fill="x")
            tf = ttk.Frame(w, padding=(10, 0, 10, 0))
            tf.pack(fill="x")
            x = self.xfer = ttk.Treeview(tf, columns=("dir", "name", "size", "prog", "speed", "status"),
                                         show="headings", height=6)
            for c, txt, wd, st in (("dir", "", 70, False), ("name", "ไฟล์", 230, True), ("size", "ขนาด", 85, False),
                                   ("prog", "ความคืบหน้า", 175, False), ("speed", "ความเร็ว", 90, False),
                                   ("status", "สถานะ", 260, True)):
                x.heading(c, text=txt)
                x.column(c, width=wd, stretch=st, anchor="e" if c in ("size", "speed") else "w")
            x.tag_configure("done", foreground=T.c("ok"))
            x.tag_configure("error", foreground=T.c("danger"))
            x.tag_configure("cancelled", foreground=T.c("muted"))
            x.pack(fill="x")
            xb = ttk.Frame(w, padding=(10, 6, 10, 10))
            xb.pack(fill="x")
            ttk.Button(xb, text="ยกเลิกที่เลือก", command=self.cancel_sel).pack(side="left")
            ttk.Button(xb, text="ล้างรายการที่เสร็จแล้ว", command=self.clear_done).pack(side="left", padx=4)
            self.status = tk.StringVar(value="")
            ttk.Label(xb, textvariable=self.status, style="Muted.TLabel").pack(side="right")
            self.go(None)
            self.win.after(150, self._poll)

        def _dl_dir(self):
            d = self.app.cfg.get("download_dir") or os.path.join(os.path.expanduser("~"), "Downloads")
            return d if os.path.isdir(d) else os.path.expanduser("~")

        def show(self):
            self.win.deiconify()
            self.win.lift()

        # ----- browsing -----
        def go(self, path):
            self.pending = self.fc.list(path, self.hidden_var.get())
            self.status.set("กำลังโหลดรายการไฟล์…")

        def refresh(self):
            self.go(self.cur_path)

        def go_up(self):
            if self.parent_path is not None:
                self.go(self.parent_path)

        def _populate(self, d):
            self.cur_path, self.parent_path = d.get("path"), d.get("parent")
            self.path_var.set(self.cur_path or ("(ไดรฟ์ทั้งหมด)" if SYSTEM != "Darwin" else ""))
            t = self.tree
            t.delete(*t.get_children(""))
            self.entries.clear()
            for i, e in enumerate(d.get("entries", [])):
                iid = "e%d" % i
                self.entries[iid] = e
                mt = datetime.fromtimestamp(e["m"]).strftime("%Y-%m-%d %H:%M") if e.get("m") else ""
                t.insert("", "end", iid=iid, values=(("📁  " if e["d"] else "📄  ") + e["n"],
                                                     "" if e["d"] else fmt_size(e["s"]), mt))
            self.status.set("%d รายการ" % len(self.entries))

        def on_open(self, e=None):
            sel = self.tree.selection()
            if not sel:
                return
            ent = self.entries.get(sel[0])
            if ent and ent["d"]:
                self.go(ent["p"])
            elif ent:
                self.download([ent["p"]])

        # ----- actions -----
        def _need_dir(self):
            if not self.cur_path:
                messagebox.showinfo(APP, "เปิดโฟลเดอร์ปลายทางที่ต้องการก่อน", parent=self.win)
                return False
            return True

        def upload_files(self):
            if not self._need_dir():
                return
            try:
                paths = pick_files(self.win, "เลือกไฟล์ที่จะอัปโหลด")
                if paths:
                    self._add_job(self.fc.upload(list(paths), self.cur_path))
            except Exception as e:
                log_error(e)
                messagebox.showerror(APP, "อัปโหลดไม่ได้: %s" % err_text(e), parent=self.win)

        def upload_folder(self):
            if not self._need_dir():
                return
            try:
                d = pick_folder(self.win, "เลือกโฟลเดอร์ที่จะอัปโหลด")
                if d:
                    self._add_job(self.fc.upload([d], self.cur_path))
            except Exception as e:
                log_error(e)
                messagebox.showerror(APP, "อัปโหลดไม่ได้: %s" % err_text(e), parent=self.win)

        def download(self, paths=None):
            if paths is None:
                paths = [self.entries[i]["p"] for i in self.tree.selection() if i in self.entries]
            if not paths:
                messagebox.showinfo(APP, "เลือกไฟล์หรือโฟลเดอร์ที่จะดาวน์โหลดก่อน", parent=self.win)
                return
            dest = self.dl_var.get()
            try:
                os.makedirs(dest, exist_ok=True)
            except OSError as e:
                messagebox.showerror(APP, "ใช้โฟลเดอร์นี้ไม่ได้: %s" % err_text(e), parent=self.win)
                return
            self._add_job(self.fc.download(paths, dest))

        def mkdir(self):
            if not self._need_dir():
                return
            name = simpledialog.askstring(APP, "ชื่อโฟลเดอร์ใหม่:", parent=self.win)
            if name and name.strip():
                self.pending = self.fc.mkdir(self.cur_path, name.strip(), self.hidden_var.get())

        def change_dl(self):
            d = pick_folder(self.win, "เลือกโฟลเดอร์สำหรับเก็บไฟล์ที่ดาวน์โหลด", self.dl_var.get())
            if d:
                self.dl_var.set(d)
                self.app.cfg["download_dir"] = d
                save_config(self.app.cfg)

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
                el = max(0.001, (job["t1"] or now) - job["t0"])
                spd = cur / el
            arrow = "⬆ ส่ง" if job["dir"] == "up" else "⬇ รับ"
            return (arrow, job["name"], fmt_size(total) if total else "-", "%s %3.0f%%" % (bar, pct),
                    "%s/s" % fmt_size(spd) if cur else "", job["status"])

        def _poll(self):
            if self.v.closed:
                return
            try:
                while True:
                    kind, d = self.fc.events.get_nowait()
                    if kind == "fs" and d.get("id") == self.pending:
                        if d.get("ok"):
                            self._populate(d)
                        else:
                            self.status.set("✗ %s" % d.get("err"))
                            messagebox.showerror(APP, d.get("err") or "ผิดพลาด", parent=self.win)
                    elif kind == "job_done":
                        job = self.fc.jobs.get(d)
                        if job and job["state"] == "done":
                            if job["dir"] == "up" and job["dest"] == self.cur_path:
                                self.refresh()
                            self.status.set("%s เสร็จ: %s" % ("อัปโหลด" if job["dir"] == "up" else "ดาวน์โหลด",
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
        THEME_LABEL = {"auto": "◐  อัตโนมัติ", "light": "☀  สว่าง", "dark": "☾  มืด"}

        def __init__(self, root):
            self.root = root
            self.cfg = load_config()
            if not self.cfg.get("host_id") or not self.cfg.get("host_secret"):
                self.cfg.update({"host_id": new_host_id(), "host_secret": secrets.token_hex(24)})
                save_config(self.cfg)
            self.q = queue.Queue()
            self.server = None
            self.viewers = []
            self.banner_state = ("off", "")
            self.session_who = None
            root.title("%s — Remote Desktop" % APP)
            root.geometry("1000x720")
            root.minsize(900, 640)
            self._build_header(root)
            nb = ttk.Notebook(root)
            nb.pack(fill="both", expand=True)
            t1, t2, t3 = (ttk.Frame(nb, padding=(16, 14, 16, 16)) for _ in range(3))
            nb.add(t1, text="ควบคุมเครื่องอื่น")
            nb.add(t2, text="ให้เครื่องอื่นควบคุมเครื่องนี้")
            nb.add(t3, text="อินเทอร์เน็ต (Relay)")
            self._build_client(t1)
            self._build_server(t2)
            self._build_relay(t3)
            self._update_id_row()
            T.on_change(lambda: self._banner(*self.banner_state))
            if self.cfg.get("last_tab") in (1, 2):
                nb.select(self.cfg["last_tab"])
            nb.bind("<<NotebookTabChanged>>", lambda e: self._tab(nb))
            root.after(50, self._poll)
            if self.cfg.get("autostart"):
                root.after(300, self.start_server)

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
            lbl(txt, "Remote Desktop · LAN และอินเทอร์เน็ต · v%s" % VERSION, fg="hdr_muted", bg="header",
                font="small").pack(anchor="w")
            self.theme_btn = lbl(hdr, self.THEME_LABEL[T.mode], fg="hdr_fg", bg="header2", font="smallbold",
                                 padx=14, pady=6, cursor="hand2")
            self.theme_btn.pack(side="right", padx=18)
            self.theme_btn.bind("<Button-1>", lambda e: self.cycle_theme())

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
            P.columnconfigure(1, weight=4, uniform="c")
            P.rowconfigure(0, weight=1)
            c = card(P)
            c.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            lbl(c, "เชื่อมต่อไปยังเครื่องอื่น", font="h2").pack(anchor="w", padx=22, pady=(20, 2))
            lbl(c, "ใส่ IP (ในวง LAN) หรือ ID 9 หลัก (ผ่านอินเทอร์เน็ต) ของเครื่องปลายทาง",
                fg="muted", font="small", wraplength=420).pack(anchor="w", padx=22, pady=(0, 16))
            lbl(c, "IP หรือ ID", fg="muted", font="smallbold").pack(anchor="w", padx=22)
            self.host_var = tk.StringVar(value=(self.cfg.get("recent") or [""])[0])
            self.host_cb = ttk.Combobox(c, textvariable=self.host_var, values=self.cfg.get("recent", []),
                                        font=T.f["big"])
            self.host_cb.pack(fill="x", padx=22, pady=(4, 14))
            lbl(c, "รหัสผ่าน", fg="muted", font="smallbold").pack(anchor="w", padx=22)
            self.cpw_var = tk.StringVar()
            pw = ttk.Entry(c, textvariable=self.cpw_var, show="•", font=T.f["big"])
            pw.pack(fill="x", padx=22, pady=(4, 10))
            pw.bind("<Return>", lambda e: self.connect())
            row = box(c)
            row.pack(fill="x", padx=22)
            self.view_only_var = tk.BooleanVar(value=False)
            ttk.Checkbutton(row, text="ดูหน้าจออย่างเดียว", variable=self.view_only_var,
                            style="Card.TCheckbutton").pack(side="left")
            self.cport_var = tk.StringVar(value=str(self.cfg.get("client_port", DEFAULT_PORT)))
            ttk.Entry(row, textvariable=self.cport_var, width=6).pack(side="right")
            lbl(row, "พอร์ต (LAN)", fg="muted", font="small").pack(side="right", padx=6)
            self.conn_btn = ttk.Button(c, text="เชื่อมต่อ   →", style="Big.Accent.TButton", command=self.connect)
            self.conn_btn.pack(fill="x", padx=22, pady=(18, 10))
            self.cstatus = tk.StringVar(value="")
            lbl(c, textvariable=self.cstatus, fg="warn", font="small", wraplength=420).pack(anchor="w", padx=22)
            tips = box(c)
            tips.pack(side="bottom", fill="x", padx=22, pady=(0, 18))
            for t in ("🔒  เข้ารหัสทุกการเชื่อมต่อด้วย TLS — รหัสผ่านไม่ถูกส่งผ่านเครือข่าย",
                      "⌨  ใน หน้าต่างรีโมท: รับ-ส่งไฟล์, ส่งข้อความภาษาไทย, ดู Latency"):
                lbl(tips, t, fg="muted", font="small").pack(anchor="w", pady=1)

            d = card(P)
            d.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
            head = box(d)
            head.pack(fill="x", padx=20, pady=(20, 4))
            lbl(head, "เครื่องในวง LAN", font="h2").pack(side="left")
            self.disc_btn = ttk.Button(head, text="ค้นหา", command=self.discover)
            self.disc_btn.pack(side="right")
            lbl(d, "เครื่องที่เปิดรับการเชื่อมต่ออยู่ — ดับเบิลคลิกเพื่อเลือก", fg="muted", font="small").pack(
                anchor="w", padx=20, pady=(0, 10))
            tf = box(d)
            tf.pack(fill="both", expand=True, padx=20, pady=(0, 20))
            self.disc = ttk.Treeview(tf, columns=("ip", "name"), show="headings")
            self.disc.heading("ip", text="IP")
            self.disc.heading("name", text="ชื่อเครื่อง")
            self.disc.column("ip", width=130, stretch=False)
            self.disc.pack(fill="both", expand=True)
            self.disc.bind("<Double-1>", self._pick_disc)
            self.disc.bind("<<TreeviewSelect>>", self._pick_disc_fill)

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
            self.srv_btn = ttk.Button(self.status_btns, text="▶   เริ่มเปิดรับการเชื่อมต่อ", style="Big.Accent.TButton",
                                      command=self.toggle_server)
            self.srv_btn.pack(side="left")
            self.kick_btn = ttk.Button(self.status_btns, text="ตัดการเชื่อมต่อ", style="Big.Danger.TButton",
                                       command=self.kick)

            # ข้อมูลสำหรับเชื่อมต่อ
            info = card(left)
            info.pack(fill="x", pady=(14, 0))
            lbl(info, "ข้อมูลสำหรับให้อีกฝั่งเชื่อมต่อ", font="h2").grid(row=0, column=0, columnspan=3, sticky="w",
                                                                    padx=20, pady=(16, 10))
            lbl(info, "IP ในวง LAN", fg="muted", font="smallbold").grid(row=1, column=0, sticky="w", padx=20)
            lbl(info, "ID ผ่านอินเทอร์เน็ต", fg="muted", font="smallbold").grid(row=1, column=1, sticky="w", padx=20)
            self.ip_lbl = lbl(info, "\n".join(get_local_ips()[:2]), font="mono")
            self.ip_lbl.grid(row=2, column=0, sticky="nw", padx=20)
            self.id_lbl = lbl(info, "", font="mono")
            self.id_lbl.grid(row=2, column=1, sticky="nw", padx=20)
            self.relay_state_lbl = lbl(info, "", fg="muted", font="small", wraplength=230)
            self.relay_state_lbl.grid(row=3, column=1, sticky="nw", padx=20)
            lbl(info, "รหัสผ่าน", fg="muted", font="smallbold").grid(row=4, column=0, columnspan=2, sticky="w",
                                                                   padx=20, pady=(12, 0))
            pwrow = box(info)
            pwrow.grid(row=5, column=0, columnspan=2, sticky="we", padx=20, pady=(4, 18))
            self.spw_var = tk.StringVar(value=self.cfg.get("password") or gen_password())
            ttk.Entry(pwrow, textvariable=self.spw_var, font=T.f["mono"], width=16).pack(side="left", fill="x",
                                                                                          expand=True)
            ttk.Button(pwrow, text="สุ่มใหม่", command=lambda: self.spw_var.set(gen_password())).pack(side="left",
                                                                                                      padx=(8, 0))
            ttk.Button(pwrow, text="คัดลอก", command=self._copy_conn).pack(side="left", padx=(6, 0))
            info.columnconfigure(0, weight=1)
            info.columnconfigure(1, weight=1)

            # ตัวเลือก
            opt = card(left)
            opt.pack(fill="x", pady=(14, 0))
            lbl(opt, "ตัวเลือก", font="h2").grid(row=0, column=0, columnspan=2, sticky="w", padx=20, pady=(16, 6))
            self.ask_var = tk.BooleanVar(value=self.cfg.get("ask", True))
            self.allow_var = tk.BooleanVar(value=self.cfg.get("allow_control", True))
            self.files_var = tk.BooleanVar(value=self.cfg.get("allow_files", True))
            self.auto_var = tk.BooleanVar(value=self.cfg.get("autostart", False))
            for i, (txt, var) in enumerate((("ถามก่อนรับการเชื่อมต่อ", self.ask_var),
                                            ("อนุญาตให้ควบคุมเมาส์/คีย์บอร์ด", self.allow_var),
                                            ("อนุญาตให้รับ-ส่งไฟล์", self.files_var),
                                            ("เปิดรับอัตโนมัติเมื่อเปิดโปรแกรม", self.auto_var))):
                ttk.Checkbutton(opt, text=txt, variable=var, style="Card.TCheckbutton",
                                command=self._save_server_opts).grid(row=1 + i // 2, column=i % 2, sticky="w", padx=20)
            prow = box(opt)
            prow.grid(row=3, column=0, columnspan=2, sticky="w", padx=20, pady=(6, 16))
            lbl(prow, "พอร์ต (LAN)", fg="muted", font="small").pack(side="left")
            self.sport_var = tk.StringVar(value=str(self.cfg.get("port", DEFAULT_PORT)))
            ttk.Entry(prow, textvariable=self.sport_var, width=7).pack(side="left", padx=8)
            opt.columnconfigure(1, weight=1)

            # สิทธิ์ macOS
            self.perm_rows = {}
            if SYSTEM == "Darwin":
                pc = card(right)
                pc.pack(fill="x", pady=(0, 14))
                lbl(pc, "สิทธิ์ของ macOS", font="h2").grid(row=0, column=0, columnspan=3, sticky="w",
                                                          padx=20, pady=(16, 0))
                lbl(pc, "ให้สิทธิ์กับแอป %s" % ("NetRemote" if getattr(sys, "frozen", False) else "Terminal"),
                    fg="muted", font="small").grid(row=1, column=0, columnspan=3, sticky="w", padx=20, pady=(0, 8))
                for i, (k, label) in enumerate((("screen", "Screen Recording\nให้อีกฝั่งเห็นหน้าจอ"),
                                                ("access", "Accessibility\nให้อีกฝั่งควบคุมได้"))):
                    st = lbl(pc, "…", font="smallbold", padx=8, pady=2, anchor="center")
                    st.grid(row=2 + i, column=0, sticky="w", padx=(20, 8), pady=4)
                    lbl(pc, label, font="small").grid(row=2 + i, column=1, sticky="w")
                    ttk.Button(pc, text="เปิดการตั้งค่า", command=lambda k=k: self._open_perm(k)).grid(
                        row=2 + i, column=2, sticky="e", padx=20, pady=4)
                    self.perm_rows[k] = st
                lbl(pc, "").grid(row=4, column=0, pady=4)
                pc.columnconfigure(1, weight=1)
                self._check_perms()

            lc = card(right)
            lc.pack(fill="both", expand=True)
            lbl(lc, "บันทึกเหตุการณ์", font="h2").pack(anchor="w", padx=20, pady=(16, 8))
            self.log = T.track(tk.Listbox(lc, activestyle="none", relief="flat", highlightthickness=0, bd=0,
                                          font=T.f["small"]),
                               bg="card", fg="text", selectbackground="sel", selectforeground="text")
            self.log.pack(fill="both", expand=True, padx=20)
            try:
                fp = server_fingerprint() if os.path.exists(CERT_FILE) else "(สร้างเมื่อเริ่มเปิดรับครั้งแรก)"
            except Exception:
                fp = "-"
            self.fp_lbl = lbl(lc, "Certificate  %s" % fp[:47], fg="muted", font="small")
            self.fp_lbl.pack(anchor="w", padx=20, pady=(8, 14))
            self._banner("off")

        # ---------------- relay (internet) tab ----------------
        def _build_relay(self, P):
            P.columnconfigure(0, weight=6, uniform="r")
            P.columnconfigure(1, weight=5, uniform="r")
            P.rowconfigure(0, weight=1)
            f = card(P)
            f.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            lbl(f, "Relay Server", font="h2").pack(anchor="w", padx=22, pady=(20, 2))
            lbl(f, "ตัวกลางสำหรับรีโมทผ่านอินเทอร์เน็ต (โปรแกรม relay_server.py บน VPS / Cloud) — ทั้งสองเครื่อง"
                   "เชื่อมต่อออกไปหา Relay จึงไม่ต้องตั้ง Router และข้อมูลยังเข้ารหัสจากต้นทางถึงปลายทาง",
                fg="muted", font="small", wraplength=470).pack(anchor="w", padx=22, pady=(0, 16))
            lbl(f, "ที่อยู่ Relay Server", fg="muted", font="smallbold").pack(anchor="w", padx=22)
            self.relay_addr_var = tk.StringVar(value=self.cfg.get("relay_addr", ""))
            ttk.Entry(f, textvariable=self.relay_addr_var, font=T.f["big"]).pack(fill="x", padx=22, pady=(4, 2))
            lbl(f, "เช่น relay.example.com:5910 หรือ 203.0.113.10:5910", fg="muted", font="small").pack(
                anchor="w", padx=22, pady=(0, 12))
            lbl(f, "Relay Key", fg="muted", font="smallbold").pack(anchor="w", padx=22)
            self.relay_key_var = tk.StringVar(value=self.cfg.get("relay_key", ""))
            ttk.Entry(f, textvariable=self.relay_key_var, show="•", font=T.f["big"]).pack(fill="x", padx=22,
                                                                                          pady=(4, 12))
            self.relay_host_var = tk.BooleanVar(value=self.cfg.get("relay_host", False))
            ttk.Checkbutton(f, text="ให้เครื่องนี้รับการเชื่อมต่อผ่านอินเทอร์เน็ตด้วย", variable=self.relay_host_var,
                            style="Card.TCheckbutton").pack(anchor="w", padx=22)
            row = box(f)
            row.pack(fill="x", padx=22, pady=(16, 8))
            ttk.Button(row, text="บันทึก", style="Accent.TButton", command=self.save_relay).pack(side="left")
            ttk.Button(row, text="ทดสอบการเชื่อมต่อ", command=self.test_relay).pack(side="left", padx=8)
            self.relay_test_var = tk.StringVar(value="")
            lbl(f, textvariable=self.relay_test_var, fg="muted", font="small", wraplength=470).pack(
                anchor="w", padx=22, pady=(0, 18))

            right = ttk.Frame(P)
            right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
            idc = card(right)
            idc.pack(fill="x")
            lbl(idc, "ID ของเครื่องนี้", font="h2").pack(anchor="w", padx=22, pady=(20, 2))
            lbl(idc, "ให้อีกฝั่งใส่ ID นี้ในช่อง \"IP หรือ ID\"", fg="muted", font="small").pack(anchor="w", padx=22)
            self.relay_id_lbl = lbl(idc, fmt_id(self.cfg["host_id"]), fg="accent", font="monobig")
            self.relay_id_lbl.pack(anchor="w", padx=22, pady=(10, 8))
            ttk.Button(idc, text="สร้าง ID ใหม่", command=self.new_id).pack(anchor="w", padx=22, pady=(0, 20))
            alt = card(right)
            alt.pack(fill="both", expand=True, pady=(14, 0))
            lbl(alt, "ไม่มี Relay?", font="h2").pack(anchor="w", padx=22, pady=(20, 4))
            lbl(alt, "ตั้ง Port Forward ที่ Router ให้พอร์ต TCP %d มาที่เครื่องนี้ แล้วให้อีกฝั่งใส่ IP สาธารณะของ "
                     "Router แทน — ไม่แนะนำนัก เพราะเครื่องจะถูกสแกนจากอินเทอร์เน็ตได้ ถ้าใช้วิธีนี้ควรตั้งรหัสผ่านยาว ๆ "
                     "และเปิด \"ถามก่อนรับการเชื่อมต่อ\"" % DEFAULT_PORT,
                fg="muted", font="small", wraplength=380).pack(anchor="w", padx=22, pady=(0, 20))

        def _pick_disc_fill(self, e=None):
            sel = self.disc.selection()
            if sel:
                self.host_var.set(self.disc.item(sel[0], "values")[0])

        def _pick_disc(self, e=None):
            self._pick_disc_fill()
            if self.cpw_var.get():
                self.connect()

        def discover(self):
            try:
                port = int(self.cport_var.get())
            except ValueError:
                port = DEFAULT_PORT
            self.disc_btn.configure(state="disabled", text="กำลังค้นหา…")
            self.disc.delete(*self.disc.get_children())

            def work():
                try:
                    res = discover_lan(port)
                except Exception as e:
                    res = e
                self.q.put(("discovered", res))
            threading.Thread(target=work, daemon=True).start()

        def connect(self):
            host = self.host_var.get().strip()
            pw = self.cpw_var.get()
            if not host:
                messagebox.showerror(APP, "กรุณาใส่ IP หรือชื่อเครื่องปลายทาง")
                return
            if not pw:
                messagebox.showerror(APP, "กรุณาใส่รหัสผ่าน")
                return
            try:
                port = int(self.cport_var.get())
            except ValueError:
                messagebox.showerror(APP, "พอร์ตต้องเป็นตัวเลข")
                return
            rid = parse_id(host)
            relay = None
            if rid:
                if not self.cfg.get("relay_addr"):
                    messagebox.showerror(APP, "การเชื่อมต่อด้วย ID ต้องตั้งค่า Relay Server ก่อน\n"
                                              "ไปที่แท็บ \"อินเทอร์เน็ต (Relay)\"")
                    return
                relay = {"addr": self.cfg["relay_addr"], "key": self.cfg.get("relay_key", ""), "id": rid}
                host = "ID " + fmt_id(rid)
            self.conn_btn.configure(state="disabled")
            self.cstatus.set("กำลังเชื่อมต่อ %s%s … (ถ้าปลายทางตั้งให้ถามก่อน ต้องรอให้กดยอมรับ)"
                             % (host, " ผ่าน Relay" if relay else ""))

            def work():
                try:
                    tls, info, fp = client_connect(host, port, pw, self._confirm_fp_threadsafe, relay=relay)
                    self.q.put(("connected", host, port, tls, info, fp))
                except socket.timeout:
                    self.q.put(("connect_err", "หมดเวลา — ไม่มีการตอบรับจาก %s" % host))
                except ConnectionRefusedError:
                    self.q.put(("connect_err", "%s ไม่ได้เปิดรับการเชื่อมต่อที่พอร์ต %d" % (host, port)))
                except OSError as e:
                    msg = str(e) if isinstance(e, ConnectionError) else (e.strerror or str(e))
                    self.q.put(("connect_err", "เชื่อมต่อไม่ได้: %s" % msg))
                except Exception as e:
                    self.q.put(("connect_err", "เชื่อมต่อไม่ได้: %s" % e))
            threading.Thread(target=work, daemon=True).start()

        def _confirm_fp_threadsafe(self, host, fp, name):
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

        def save_relay(self, quiet=False):
            addr = self.relay_addr_var.get().strip()
            if addr:
                try:
                    parse_hostport(addr, RELAY_PORT)
                except ValueError:
                    messagebox.showerror(APP, "รูปแบบ Relay Server ไม่ถูกต้อง (เช่น relay.example.com:5910)")
                    return False
            self.cfg.update({"relay_addr": addr, "relay_key": self.relay_key_var.get(),
                             "relay_host": self.relay_host_var.get()})
            save_config(self.cfg)
            self._update_id_row()
            if not quiet:
                self.relay_test_var.set("บันทึกแล้ว")
                if self.server and self.server.is_alive():
                    if messagebox.askyesno(APP, "เริ่มเปิดรับการเชื่อมต่อใหม่เพื่อใช้การตั้งค่านี้เลยหรือไม่?"):
                        self.toggle_server()
                        self.root.after(400, self.start_server)
            return True

        def test_relay(self):
            if not self.save_relay(quiet=True):
                return
            addr, key = self.cfg.get("relay_addr"), self.cfg.get("relay_key")
            if not addr:
                self.relay_test_var.set("ใส่ที่อยู่ Relay Server ก่อน")
                return
            self.relay_test_var.set("กำลังทดสอบ %s …" % addr)

            def work():
                try:
                    r = relay_test(addr, key)
                    msg = "✓ เชื่อมต่อ Relay ได้ (เวอร์ชัน %s, ออนไลน์ %s เครื่อง)" % (r.get("v"), r.get("hosts"))
                except Exception as e:
                    msg = "✗ %s" % err_text(e)
                self.q.put(("relay_test", msg))
            threading.Thread(target=work, daemon=True).start()

        def new_id(self):
            if not messagebox.askyesno(APP, "สร้าง ID ใหม่? ผู้ที่เคยเชื่อมต่อด้วย ID เดิมจะต้องใช้ ID ใหม่"):
                return
            self.cfg.update({"host_id": new_host_id(), "host_secret": secrets.token_hex(24)})
            save_config(self.cfg)
            self.relay_id_lbl.configure(text=fmt_id(self.cfg["host_id"]))
            self._update_id_row()
            if self.server and self.server.is_alive():
                self.toggle_server()
                self.root.after(400, self.start_server)

        def _relay_cfg(self):
            if self.cfg.get("relay_host") and self.cfg.get("relay_addr"):
                return {"addr": self.cfg["relay_addr"], "key": self.cfg.get("relay_key", ""),
                        "id": self.cfg["host_id"], "secret": self.cfg["host_secret"]}
            return None

        def _update_id_row(self, state=None, text=None):
            if self._relay_cfg():
                self.id_lbl.configure(text=fmt_id(self.cfg["host_id"]), fg=T.c("text"))
                if text:
                    color = {"online": "ok", "error": "danger", "connecting": "warn"}.get(state, "muted")
                    self.relay_state_lbl.configure(text=("● " if state == "online" else "") + text, fg=T.c(color))
                elif not (self.server and self.server.is_alive()):
                    self.relay_state_lbl.configure(text="จะออนไลน์เมื่อกด เริ่มเปิดรับ", fg=T.c("muted"))
            else:
                self.id_lbl.configure(text="ปิดอยู่", fg=T.c("muted"))
                self.relay_state_lbl.configure(text="ตั้งค่าได้ที่แท็บ \"อินเทอร์เน็ต (Relay)\"", fg=T.c("muted"))

        def _copy_conn(self):
            txt = "NetRemote — IP: %s  พอร์ต: %s  รหัสผ่าน: %s" % (get_local_ip(), self.sport_var.get(),
                                                                  self.spw_var.get())
            if self._relay_cfg():
                txt += "  |  ผ่านอินเทอร์เน็ต ID: %s" % fmt_id(self.cfg["host_id"])
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self._log("คัดลอกข้อมูลการเชื่อมต่อแล้ว")

        def _open_perm(self, k):
            if k == "screen":
                mac_request_screen_access()
            mac_open_settings(k)

        def _check_perms(self):
            scr, acc = mac_permissions()
            for k, v in (("screen", scr), ("access", acc)):
                lbl = self.perm_rows.get(k)
                if lbl is not None:
                    lbl.configure(text="✓ อนุญาตแล้ว" if v else ("✗ ยังไม่อนุญาต" if v is False else "? ตรวจไม่ได้"),
                                  fg=T.c("ok" if v else "danger"), bg=T.c("ok_bg" if v else "danger_bg"))
            self.root.after(3000, self._check_perms)

        def _save_server_opts(self):
            self.cfg.update({"ask": self.ask_var.get(), "allow_control": self.allow_var.get(),
                             "autostart": self.auto_var.get(), "allow_files": self.files_var.get()})
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
                self.srv_btn.configure(text="▶  เริ่มเปิดรับการเชื่อมต่อ")
                self._banner("off")
                return
            self.start_server()

        def start_server(self):
            miss = missing_modules(server=True)
            if miss:
                messagebox.showerror(APP, "ยังไม่ได้ติดตั้ง: %s\n\nเปิดโปรแกรมผ่านไฟล์ \"Remote Desktop.command\" "
                                          "เพื่อติดตั้งอัตโนมัติ หรือรัน:\npip install %s" % (", ".join(miss), " ".join(miss)))
                return
            pw = self.spw_var.get().strip()
            if len(norm_pw(pw)) < 6:
                messagebox.showerror(APP, "รหัสผ่านต้องยาวอย่างน้อย 6 ตัวอักษร")
                return
            try:
                port = int(self.sport_var.get())
            except ValueError:
                messagebox.showerror(APP, "พอร์ตต้องเป็นตัวเลข")
                return
            self.cfg.update({"password": pw, "port": port})
            save_config(self.cfg)
            try:
                self.server = Server(port, pw, self.q, self._ask_threadsafe if self.ask_var.get() else None,
                                     self.allow_var.get(), self.files_var.get(), relay=self._relay_cfg())
            except Exception as e:
                messagebox.showerror(APP, "เริ่มไม่ได้: %s" % e)
                return
            self.fp_lbl.configure(text="Certificate: %s" % self.server.fp[:47])
            self.server.start()
            self.srv_btn.configure(text="■  หยุดเปิดรับ")
            self._banner("wait")
            if SYSTEM == "Darwin":
                scr, acc = mac_permissions()
                if scr is False:
                    mac_request_screen_access()
                    self._log("⚠ ยังไม่ได้อนุญาต Screen Recording — อีกฝั่งจะเห็นแค่ภาพพื้นหลัง")
                if acc is False:
                    self._log("⚠ ยังไม่ได้อนุญาต Accessibility — อีกฝั่งจะควบคุมไม่ได้")

        def kick(self):
            if self.server:
                self.server.kick()

        def _banner(self, state, who="", sub=None):
            self.banner_state = (state, who)
            if state == "off":
                bg, fg, border = "card", "muted", "border"
                title = "○   ยังไม่เปิดรับการเชื่อมต่อ"
                sub = "กด \"เริ่มเปิดรับการเชื่อมต่อ\" เพื่อให้เครื่องอื่นเชื่อมต่อเข้ามาได้"
            elif state == "wait":
                bg, fg, border = "ok_bg", "ok", "ok_bg"
                title = "●   พร้อมรับการเชื่อมต่อ"
                sub = "รอที่พอร์ต %s ในวง LAN%s" % (self.sport_var.get(), (" และผ่านอินเทอร์เน็ตด้วย ID %s"
                                                   % fmt_id(self.cfg["host_id"])) if self._relay_cfg() else "")
            else:
                self.session_who = who
                bg, fg, border = "danger_bg", "danger", "danger_bg"
                title = "●   กำลังถูกควบคุมอยู่"
                sub = sub or "โดย %s" % who
            for w in (self.status_card, self.status_btns):
                w.configure(bg=T.c(bg))
            self.status_card.configure(highlightbackground=T.c(border), highlightcolor=T.c(border))
            self.banner.configure(text=title, bg=T.c(bg), fg=T.c(fg))
            self.banner_sub.configure(text=sub, bg=T.c(bg), fg=T.c("text" if state != "off" else "muted"))
            running = state != "off"
            self.srv_btn.configure(text="■   หยุดเปิดรับ" if running else "▶   เริ่มเปิดรับการเชื่อมต่อ",
                                   style="Big.TButton" if running else "Big.Accent.TButton")
            if state == "busy":
                self.kick_btn.pack(side="left", padx=(10, 0))
            else:
                self.kick_btn.pack_forget()

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
                        _, host, port, tls, info, fp = m
                        self.conn_btn.configure(state="normal")
                        self.cstatus.set("")
                        rec = [host] + [h for h in self.cfg.get("recent", []) if h != host]
                        self.cfg.update({"recent": rec[:15], "client_port": port})
                        save_config(self.cfg)
                        self.host_cb.configure(values=rec[:15])
                        self.viewers.append(Viewer(self, tls, info, host, fp))
                    elif k == "connect_err":
                        self.conn_btn.configure(state="normal")
                        self.cstatus.set(m[1])
                    elif k == "viewer_closed":
                        v, reason = m[1], m[2]
                        if v in self.viewers:
                            self.viewers.remove(v)
                        if not v.closed:
                            v.destroy()
                            messagebox.showinfo(APP, "การเชื่อมต่อกับ %s สิ้นสุด\n%s" % (v.host, reason))
                    elif k == "discovered":
                        self.disc_btn.configure(state="normal", text="ค้นหา")
                        res = m[1]
                        if isinstance(res, Exception):
                            messagebox.showerror(APP, "ค้นหาไม่สำเร็จ: %s" % res)
                        elif not res:
                            self.disc.insert("", "end", values=("-", "ไม่พบเครื่องที่เปิดรับในวง LAN นี้"))
                        for ip, name, own in (res if isinstance(res, list) else []):
                            self.disc.insert("", "end", values=(ip, (name or "-") + ("  (เครื่องนี้)" if own else "")))
                    elif k == "ask_fp":
                        _, host, old, fp, name, ev, box = m
                        box["ok"] = messagebox.askyesno(
                            APP, "⚠ Certificate ของ %s (%s) เปลี่ยนไปจากที่เคยเชื่อมต่อ\n\nเดิม: %s\nใหม่: %s\n\n"
                                 "ถ้าปลายทางไม่ได้ติดตั้งโปรแกรมใหม่ อาจมีผู้ดักข้อมูลกลางทาง\nต้องการเชื่อมต่อต่อหรือไม่?"
                                 % (name, host, old[:47], fp[:47]), icon="warning", default="no")
                        ev.set()
                    elif k == "ask_accept":
                        _, ip, name, ev, box = m
                        self.root.deiconify()
                        self.root.lift()
                        self.root.attributes("-topmost", True)
                        box["ok"] = messagebox.askyesno(
                            APP, "%s (%s)\nขอเชื่อมต่อเพื่อ%sเครื่องนี้\n\nอนุญาตหรือไม่?"
                                 % (name, ip, "ควบคุม" if self.allow_var.get() else "ดูหน้าจอ"), parent=self.root)
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
                    elif k == "relay_test":
                        self.relay_test_var.set(m[1])
                    elif k == "latency":
                        if getattr(self, "session_who", None) and self.server and self.server.session:
                            word, _c = latency_style(m[2])
                            self._banner("busy", self.session_who, "โดย %s   ·   Latency %.0f ms (%s)"
                                         % (self.session_who, m[2], word))
                    elif k == "session_end":
                        self.session_who = None
                        self._banner("wait" if self.server and self.server.is_alive() else "off")
                    elif k == "server_err":
                        self._log(m[1])
                        messagebox.showerror(APP, m[1])
                        self.server = None
                        self.srv_btn.configure(text="▶  เริ่มเปิดรับการเชื่อมต่อ")
                        self._banner("off")
            except queue.Empty:
                pass
            self.root.after(50, self._poll)

        def quit(self):
            for v in list(self.viewers):
                v.disconnect()
            if self.server:
                self.server.stop()
            self.root.after(200, self.root.destroy)

    root = tk.Tk()
    T = Theme(root, load_config().get("theme", "auto"))
    set_app_icon(root)
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.quit)
    if SYSTEM == "Darwin":
        try:
            root.createcommand("tk::mac::Quit", app.quit)
        except Exception:
            pass
    root.mainloop()


# ============================================================================
# โหมดไม่มีหน้าต่าง
# ============================================================================
def run_headless_server(args):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    cfg = load_config()
    pw = args.password or cfg.get("password") or gen_password()
    port = args.port or cfg.get("port", DEFAULT_PORT)
    cfg.update({"password": pw, "port": port})
    save_config(cfg)
    q = queue.Queue()
    relay = None
    if args.relay:
        if not cfg.get("host_id") or not cfg.get("host_secret"):
            cfg.update({"host_id": new_host_id(), "host_secret": secrets.token_hex(24)})
            save_config(cfg)
        relay = {"addr": args.relay, "key": args.relay_key or "", "id": cfg["host_id"], "secret": cfg["host_secret"]}
    srv = Server(port, pw, q, None, not args.view_only, not args.no_files, relay=relay)
    print("%s %s — เปิดรับการเชื่อมต่อ" % (APP, VERSION))
    print("  IP       : %s" % "  ".join(get_local_ips()))
    print("  พอร์ต    : %d" % port)
    print("  รหัสผ่าน : %s" % pw)
    print("  Cert     : %s" % srv.fp[:47])
    if relay:
        print("  ID       : %s  (ผ่าน Relay %s)" % (fmt_id(relay["id"]), args.relay))
    print("กด Ctrl+C เพื่อหยุด\n")
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
    except KeyboardInterrupt:
        srv.stop()
        print("\nหยุดแล้ว")
    return 0


def main():
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 4096 if hard == resource.RLIM_INFINITY else min(4096, hard)
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    except Exception:
        pass
    p = argparse.ArgumentParser(description="NetRemote — Remote Desktop สำหรับวง LAN")
    p.add_argument("--server", action="store_true", help="เปิดรับการเชื่อมต่อแบบไม่มีหน้าต่าง")
    p.add_argument("--password", help="รหัสผ่าน (โหมด --server)")
    p.add_argument("--port", type=int, help="พอร์ต (ค่าเริ่มต้น %d)" % DEFAULT_PORT)
    p.add_argument("--view-only", action="store_true", help="ให้ดูหน้าจออย่างเดียว (โหมด --server)")
    p.add_argument("--no-files", action="store_true", help="ไม่อนุญาตรับ-ส่งไฟล์ (โหมด --server)")
    p.add_argument("--relay", help="Relay Server สำหรับเชื่อมต่อผ่านอินเทอร์เน็ต เช่น relay.example.com:5910")
    p.add_argument("--relay-key", help="Relay Key")
    args = p.parse_args()
    if args.server:
        miss = missing_modules(server=True)
        if miss:
            print("ยังไม่ได้ติดตั้ง: pip install " + " ".join(miss))
            return 1
        return run_headless_server(args)
    miss = missing_modules(server=False)
    if miss:
        print("ยังไม่ได้ติดตั้ง: pip install " + " ".join(miss))
        return 1
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
