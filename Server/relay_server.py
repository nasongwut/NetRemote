#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRemote Relay Server — ตัวกลางสำหรับรีโมทผ่านอินเทอร์เน็ต + หน้าเว็บมอนิเตอร์
=================================================================================
ติดตั้งบนเครื่องที่มี IP สาธารณะ (VPS / Cloud / Server ที่เปิดพอร์ตได้)
ใช้แค่ Python 3.8+ ไม่ต้องติดตั้งไลบรารีเพิ่ม

    python3 relay_server.py --port 5910 --key รหัสสำหรับใช้Relay

หน้ามอนิเตอร์ (ดูว่ามีใครเชื่อมต่ออยู่บ้าง):  http://localhost:5911
    ค่าเริ่มต้นเปิดให้ดูได้จากเครื่องนี้เท่านั้น — ถ้าจะเปิดจากเครื่องอื่นใช้  --web-bind 0.0.0.0
    (ต้องใส่รหัส Admin = --admin-key หรือ Relay Key)

การทำงาน
  - เครื่องที่ถูกควบคุม (host) เชื่อมต่อเข้ามาลงทะเบียน ID 9 หลัก และค้างการเชื่อมต่อไว้
  - เครื่องที่ควบคุม (client) ขอเชื่อมต่อไปยัง ID นั้น
  - Relay สั่งให้ host เปิดการเชื่อมต่อข้อมูลใหม่ แล้วต่อท่อ (pipe) ระหว่าง client ↔ host
  - ข้อมูลภายในท่อเข้ารหัส TLS จากต้นทางถึงปลายทาง — Relay อ่านหน้าจอ/ไฟล์/รหัสผ่านไม่ได้
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import shutil
import socket
import sys
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.6"
ID_RE = re.compile(r"^\d{9}$")


def log(*a):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *a, flush=True)


def line_send(sock, obj):
    sock.sendall(json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n")


def line_recv(sock, limit=8192):
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("closed")
        if b == b"\n":
            return json.loads(buf.decode("utf-8"))
        buf += b
        if len(buf) > limit:
            raise ConnectionError("line too long")


# ข้อความเหตุการณ์ภาษาอังกฤษ (หน้ามอนิเตอร์แสดงได้ 2 ภาษา)
EVENT_EN = [
    ("NetRemote Relay %s เริ่มทำงานที่พอร์ต %d %s", "NetRemote Relay %s started on port %d %s"),
    ("Relay Key ผิดจาก %s", "Wrong Server Key from %s"),
    ("มีเครื่องพยายามใช้ ID %s ซ้ำ จาก %s (ปฏิเสธแล้ว)", "A computer tried to reuse ID %s from %s (rejected)"),
    ("เครื่อง %s (ID %s, %s) ออนไลน์", "%s (ID %s, %s) is online"),
    ("เครื่อง %s (ID %s) ออฟไลน์", "%s (ID %s) went offline"),
    ("%s ขอเชื่อมต่อ ID %s แต่เครื่องไม่ออนไลน์", "%s requested ID %s but it is offline"),
    ("%s เริ่มควบคุมเครื่อง %s (ID %s) — เชื่อมต่อตรง ไม่ผ่าน Relay", "%s started controlling %s (ID %s) — direct, not via Relay"),
    ("%s เลิกควบคุมเครื่อง %s (ID %s) — เชื่อมต่อตรง, %s", "%s stopped controlling %s (ID %s) — direct, %s"),
    ("%s เริ่มควบคุมเครื่อง %s (ID %s) — ผ่าน Relay: %s", "%s started controlling %s (ID %s) — via Relay: %s"),
    ("%s เริ่มควบคุมเครื่อง %s (ID %s)", "%s started controlling %s (ID %s)"),
    ("%s เลิกควบคุมเครื่อง %s (ID %s) — %s, %.1f MB", "%s stopped controlling %s (ID %s) — %s, %.1f MB"),
    ("%s ดาวน์โหลดอัปเดต %s (%s)", "%s downloaded update %s (%s)"),
    ("ผู้ดูแลตัดการเชื่อมต่อ %s → ID %s", "Admin ended session %s → ID %s"),
    ("ผู้ดูแลตัดเครื่อง ID %s ออกจาก Relay (เครื่องจะเชื่อมต่อกลับเองภายหลัง)",
     "Admin removed ID %s from the Relay (it will reconnect by itself later)"),
    ("เข้าสู่ระบบหน้ามอนิเตอร์ไม่สำเร็จจาก %s", "Failed monitor sign-in from %s"),
    ("ผู้ดูแลเข้าสู่ระบบหน้ามอนิเตอร์จาก %s", "Admin signed in to the monitor from %s"),
    ("ผู้ดูแลบันทึกการตั้งค่า: %s", "Admin saved settings: %s"),
    ("ผู้ดูแลโหลดการตั้งค่าใหม่: %s", "Admin reloaded settings: %s"),
    ("ผู้ดูแลสั่งรีสตาร์ต Relay", "Admin restarted the Relay"),
    ("ผู้ดูแลเผยแพร่อัปเดตโปรแกรมเวอร์ชัน %s", "Admin published app update %s"),
    ("ผู้ดูแลหยุดแจกอัปเดตโปรแกรม", "Admin stopped offering app updates"),
]
WHY_TH = {"unreachable": "สองเครื่องต่อหากันตรงไม่ได้ (Firewall/Router)",
          "host_old": "เครื่องปลายทางใช้โปรแกรมเวอร์ชันเก่า",
          "host_off": "เครื่องปลายทางปิดการเชื่อมต่อตรง",
          "client_off": "เครื่องที่ควบคุมใช้เวอร์ชันเก่าหรือปิดการเชื่อมต่อตรง"}
WHY_EN = {"unreachable": "the two computers cannot reach each other (firewall/router)",
          "host_old": "the remote computer runs an old version",
          "host_off": "direct connection is off on the remote computer",
          "client_off": "the controlling computer runs an old version or has direct connection off"}
EVENT_WORDS = [(WHY_TH[k], WHY_EN[k]) for k in WHY_TH] + [("(ใช้ Relay Key)", "(Server Key required)"), ("(ไม่มี Relay Key — ใครก็ใช้ได้)", "(no Server Key — open to anyone)")]


def _fmt_regex(fmt):
    out, i = "", 0
    for m in re.finditer(r"%[-0-9.]*[sdf]", fmt):
        out += re.escape(fmt[i:m.start()]) + ("(.*?)" if m.group().endswith("s") else r"([\d.]+)")
        i = m.end()
    return re.compile("^" + out + re.escape(fmt[i:]) + "$", re.S)


_EVENT_RX = [(_fmt_regex(th), en) for th, en in EVENT_EN]


def event_en(text):
    for rx, en in _EVENT_RX:
        m = rx.match(text)
        if m:
            parts = re.split(r"%[-0-9.]*[sdf]", en)
            out = parts[0]
            for g, p in zip(m.groups(), parts[1:]):
                for th_w, en_w in EVENT_WORDS:
                    g = g.replace(th_w, en_w)
                out += g + p
            return out
    return text


class HostConn:
    def __init__(self, sock, ip, name, app=""):
        self.sock, self.ip, self.name, self.app = sock, ip, name, app
        self.lock = threading.Lock()
        self.since = time.time()

    def send(self, obj):
        with self.lock:
            line_send(self.sock, obj)


class Relay:
    def __init__(self, port, key, store, max_sessions, updates_dir=""):
        self.port, self.key, self.store = port, key or "", store
        self.updates_dir = updates_dir
        self.default_updates = updates_dir
        self._sha_cache = {}
        self.max_sessions = max_sessions
        self.hosts = {}
        self.pending = {}
        self.sessions = {}
        self.lock = threading.Lock()
        self.rate = defaultdict(deque)
        self.bad = defaultdict(deque)
        self.events = deque(maxlen=300)
        self.started = time.time()
        self.stats = {"sessions_total": 0, "bytes_total": 0, "auth_fail": 0}
        self.samples = {}
        self.secrets = {}
        try:
            with open(store, encoding="utf-8") as f:
                self.secrets = json.load(f)
        except Exception:
            pass

    # ----- helpers -----
    def bytes_now(self):
        with self.lock:
            live = sum(s["up"] + s["down"] for s in self.sessions.values())
        return self.stats["bytes_total"] + live

    def admin_key(self):
        """รหัสเข้าหน้ามอนิเตอร์ — "" = ไม่ต้องเข้าสู่ระบบ (เปิดดูจากเครื่องนี้เท่านั้น และไม่ได้ตั้ง RELAY_ADMIN_KEY)"""
        c = getattr(self, "conf", None)
        if c is None:
            return self.key
        explicit = c.running["RELAY_ADMIN_KEY"]
        if c.started["RELAY_WEB_BIND"] in ("127.0.0.1", "localhost", "::1") and not explicit:
            return ""
        return explicit or self.key or c.generated_admin

    def apply_settings(self, why="reload"):
        """อ่านไฟล์ .env ใหม่ แล้วใช้ค่าที่เปลี่ยนได้ทันที — คืน (ค่าที่เปลี่ยน, ค่าที่ต้องรีสตาร์ต)"""
        c = self.conf
        fv = parse_env_file(c.env_path)
        changed = []
        for k, _typ, live, _d, _f in SETTINGS:
            want = c.wanted(k, fv)
            if live and want != c.running[k]:
                c.running[k] = want
                changed.append(k)
        self.key = c.running["RELAY_KEY"]
        try:
            self.max_sessions = int(c.running["RELAY_MAX_SESSIONS"])
        except ValueError:
            pass
        self.updates_dir = c.running["RELAY_UPDATES_DIR"] or self.default_updates
        self._sha_cache.clear()
        pending = [k for k, _t, live, _d, _f in SETTINGS if not live and c.wanted(k, fv) != c.started[k]]
        if changed:
            self.event("info", ("ผู้ดูแลบันทึกการตั้งค่า: %s" if why == "save" else "ผู้ดูแลโหลดการตั้งค่าใหม่: %s")
                       % ", ".join(changed))
        return changed, pending

    def settings_view(self):
        c = self.conf
        fv = parse_env_file(c.env_path)
        items = []
        for k, typ, live, d, _f in SETTINGS:
            items.append({"key": k, "type": typ, "live": live, "default": d, "value": c.wanted(k, fv),
                          "running": c.running[k] if live else c.started[k], "source": c.source(k),
                          "locked": c.source(k) in ("cli", "environment"),
                          "pending": (not live) and c.wanted(k, fv) != c.started[k]})
        return {"env_path": c.env_path, "env_exists": bool(c.env_path and os.path.isfile(c.env_path)),
                "items": items, "pending": [i["key"] for i in items if i["pending"]],
                "default_updates": self.default_updates}

    def event(self, kind, text):
        log(text)
        self.events.appendleft({"t": time.time(), "kind": kind, "text": text, "en": event_en(text)})

    def _save(self):
        try:
            tmp = self.store + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.secrets, f)
            os.replace(tmp, self.store)
        except Exception as e:
            log("save error:", e)

    def _limited(self, ip, table, n, window):
        now = time.time()
        dq = table[ip]
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(dq) >= n:
            return True
        dq.append(now)
        return False

    def _key_ok(self, msg):
        return not self.key or hmac.compare_digest(str(msg.get("key", "")), self.key)

    # ----- main -----
    def serve(self):
        ls = None
        if socket.has_ipv6:                       # รับทั้ง IPv6 และ IPv4 ถ้าเครื่องรองรับ
            try:
                ls = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                ls.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                ls.bind(("::", self.port))
            except OSError:
                if ls:
                    ls.close()
                ls = None
        if ls is None:
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind(("0.0.0.0", self.port))
        ls.listen(128)
        self.event("info", "NetRemote Relay %s เริ่มทำงานที่พอร์ต %d %s" % (
            VERSION, self.port, "(ใช้ Relay Key)" if self.key else "(ไม่มี Relay Key — ใครก็ใช้ได้)"))
        while True:
            conn, addr = ls.accept()
            threading.Thread(target=self.handle, args=(conn, addr), daemon=True).start()

    def handle(self, conn, addr):
        ip = addr[0].replace("::ffff:", "")
        handed_off = False
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(15)
            if self._limited(ip, self.rate, 60, 60):
                return
            msg = line_recv(conn)
            role = msg.get("role")
            if role == "data":
                handed_off = self._data(conn, msg)
                return
            if not self._key_ok(msg):
                self._limited(ip, self.bad, 1000, 300)
                if len(self.bad[ip]) > 10:
                    time.sleep(2)
                line_send(conn, {"ok": False, "err": "Relay Key ไม่ถูกต้อง"})
                self.stats["auth_fail"] += 1
                self.event("warn", "Relay Key ผิดจาก %s" % ip)
                return
            if role == "ping":
                line_send(conn, {"ok": True, "v": VERSION, "hosts": len(self.hosts), "sessions": len(self.sessions)})
            elif role == "update_info":
                line_send(conn, self.update_info())
            elif role == "update_get":
                conn.settimeout(120)
                self._send_update(conn, ip, str(msg.get("plat", "")))
            elif role == "host":
                self._host(conn, ip, msg)
            elif role == "client":
                handed_off = self._client(conn, ip, msg)
        except Exception:
            pass
        finally:
            if not handed_off:
                try:
                    conn.close()
                except Exception:
                    pass

    def _host(self, conn, ip, msg):
        hid = str(msg.get("id", ""))
        secret = str(msg.get("secret", ""))
        if not ID_RE.match(hid) or len(secret) < 16:
            line_send(conn, {"ok": False, "err": "ID ไม่ถูกต้อง"})
            return
        h = hashlib.sha256(secret.encode()).hexdigest()
        with self.lock:
            known = self.secrets.get(hid)
            if known and not hmac.compare_digest(known, h):
                line_send(conn, {"ok": False, "err": "ID นี้ถูกใช้โดยเครื่องอื่นแล้ว — สร้าง ID ใหม่"})
                self.event("warn", "มีเครื่องพยายามใช้ ID %s ซ้ำ จาก %s (ปฏิเสธแล้ว)" % (hid, ip))
                return
            if not known:
                self.secrets[hid] = h
                self._save()
            old = self.hosts.get(hid)
            hc = HostConn(conn, ip, str(msg.get("name", ""))[:60], str(msg.get("app", ""))[:20])
            self.hosts[hid] = hc
        if old:
            try:
                old.sock.close()
            except Exception:
                pass
        line_send(conn, {"ok": True, "v": VERSION})
        self.event("online", "เครื่อง %s (ID %s, %s) ออนไลน์" % (hc.name or "-", hid, ip))
        conn.settimeout(90)
        try:
            while True:
                m = line_recv(conn)
                if m.get("cmd") == "ping":
                    hc.send({"cmd": "pong"})
                elif m.get("cmd") == "cands":
                    with self.lock:
                        pend = self.pending.get(str(m.get("token", "")))
                    if pend is not None and pend["cands"] is None:
                        pend["cands"] = m
                        pend["ev"].set()
        except Exception:
            pass
        finally:
            with self.lock:
                if self.hosts.get(hid) is hc:
                    del self.hosts[hid]
                    gone = True
                else:
                    gone = False
            if gone:
                self.event("offline", "เครื่อง %s (ID %s) ออฟไลน์" % (hc.name or "-", hid))

    def _client(self, conn, ip, msg):
        hid = re.sub(r"\D", "", str(msg.get("id", "")))
        with self.lock:
            hc = self.hosts.get(hid)
            busy = len(self.sessions) >= self.max_sessions
        if busy:
            line_send(conn, {"ok": False, "err": "Relay มีผู้ใช้งานเต็มแล้ว ลองใหม่ภายหลัง"})
            return False
        if not hc:
            line_send(conn, {"ok": False, "err": ("Computer ID %s not found, or it is not accepting connections"
                                                  if msg.get("lang") == "en" else
                                                  "ไม่พบเครื่อง ID %s หรือเครื่องนั้นไม่ได้เปิดรับการเชื่อมต่อ") % hid})
            self.event("warn", "%s ขอเชื่อมต่อ ID %s แต่เครื่องไม่ออนไลน์" % (ip, hid))
            return False
        token = secrets.token_hex(16)
        want_direct = bool(msg.get("direct"))
        pend = {"ev": threading.Event(), "sock": None, "cands": None}
        with self.lock:
            self.pending[token] = pend
        try:
            hc.send({"cmd": "connect", "token": token, "from": ip, "direct": 1 if want_direct else 0,
                     "p2p": int(msg.get("p2p") or 0), "ccands": [str(x) for x in (msg.get("ccands") or [])][:10]})
            why = "client_off" if not want_direct else ""
            pend["ev"].wait(15)
            c = pend["cands"]
            if pend["sock"] is None and c is not None:
                # ① ลองเชื่อมต่อตรงก่อน — ส่งรายการที่อยู่ของเครื่องปลายทางให้ Client ลอง
                cands = [str(x) for x in (c.get("lan") or [])][:8]
                if c.get("fixed") and c.get("port"):
                    pub = "%s:%d" % (hc.ip, int(c["port"]))
                    if pub not in cands:
                        cands.append(pub)
                line_send(conn, {"ok": True, "phase": "direct", "cands": cands, "token": token,
                                 "hp2p": int(c.get("p2p") or 0)})
                conn.settimeout(30)
                r = line_recv(conn)
                if r.get("use") == "direct":
                    with self.lock:
                        self.pending.pop(token, None)
                    self._direct_session(conn, ip, hid, hc, str(r.get("how", ""))[:120])
                    return False
                why = "unreachable"
                log("ต่อตรงไม่สำเร็จ %s → ID %s: %s | ฝั่งควบคุม: %s" % (
                    ip, hid, str(r.get("why", ""))[:300], ", ".join(str(x) for x in (r.get("mine") or []))[:300]))
                # ② ต่อตรงไม่ได้ → ใช้ Relay
                pend["ev"].clear()
                hc.send({"cmd": "open", "token": token})
                pend["ev"].wait(15)
        except Exception:
            with self.lock:
                self.pending.pop(token, None)
            try:
                line_send(conn, {"ok": False, "err": "เครื่องปลายทางไม่ตอบสนอง"})
            except Exception:
                pass
            return False
        with self.lock:
            self.pending.pop(token, None)
        if pend["sock"] is None:
            line_send(conn, {"ok": False, "err": "เครื่องปลายทางไม่ตอบสนอง"})
            return False
        if want_direct and not why:
            why = "host_old" if not hc.app or hc.app < "1.2" else "host_off"
        line_send(conn, {"ok": True, "route": "relay"})
        threading.Thread(target=self._pipe, args=(conn, pend["sock"], ip, hid, hc, why), daemon=True).start()
        return True

    def _direct_session(self, conn, ip, hid, hc, how=""):
        """สองเครื่องเชื่อมต่อกันตรงแล้ว — ข้อมูลไม่ผ่าน Relay; Client เปิดช่องนี้ค้างไว้เพื่อแสดงในหน้ามอนิเตอร์"""
        sid = secrets.token_hex(6)
        sess = {"sid": sid, "client": ip, "hid": hid, "hname": hc.name, "hip": hc.ip, "mode": "direct", "how": how,
                "start": time.time(), "up": 0, "down": 0, "socks": (conn,), "hc": hc}
        with self.lock:
            self.sessions[sid] = sess
            self.stats["sessions_total"] += 1
            self.stats["direct_total"] = self.stats.get("direct_total", 0) + 1
        self.event("connect", "%s เริ่มควบคุมเครื่อง %s (ID %s) — เชื่อมต่อตรง ไม่ผ่าน Relay" % (ip, hc.name or "-", hid))
        conn.settimeout(None)
        try:
            while conn.recv(1024):
                pass
        except OSError:
            pass
        with self.lock:
            self.sessions.pop(sid, None)
            self.samples.pop(sid, None)
        self.event("disconnect", "%s เลิกควบคุมเครื่อง %s (ID %s) — เชื่อมต่อตรง, %s" % (
            ip, hc.name or "-", hid, fmt_dur(time.time() - sess["start"])))

    def _data(self, conn, msg):
        with self.lock:
            pend = self.pending.get(str(msg.get("token", "")))
            if not pend or pend["sock"] is not None:
                return False
            pend["sock"] = conn
        pend["ev"].set()
        return True

    def _pipe(self, a, b, ip, hid, hc, why=""):
        sid = secrets.token_hex(6)
        sess = {"sid": sid, "client": ip, "hid": hid, "hname": hc.name, "hip": hc.ip, "mode": "relay", "why": why,
                "start": time.time(), "up": 0, "down": 0, "socks": (a, b)}
        with self.lock:
            self.sessions[sid] = sess
            self.stats["sessions_total"] += 1
        self.event("connect", "%s เริ่มควบคุมเครื่อง %s (ID %s) — ผ่าน Relay: %s" % (ip, hc.name or "-", hid, WHY_TH.get(why, why or "-")))
        a.settimeout(None)
        b.settimeout(None)

        def copy(src, dst, key):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
                    sess[key] += len(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=copy, args=(b, a, "down"), daemon=True)
        t.start()
        copy(a, b, "up")
        t.join()
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass
        with self.lock:
            self.sessions.pop(sid, None)
            self.samples.pop(sid, None)
            self.stats["bytes_total"] += sess["up"] + sess["down"]
        mb = (sess["up"] + sess["down"]) / 1024 / 1024
        self.event("disconnect", "%s เลิกควบคุมเครื่อง %s (ID %s) — %s, %.1f MB" % (
            ip, hc.name or "-", hid, fmt_dur(time.time() - sess["start"]), mb))

    # ----- อัปเดตโปรแกรม (โฟลเดอร์ updates/) -----
    def _sha256(self, path):
        st = os.stat(path)
        key = (path, st.st_mtime, st.st_size)
        if key not in self._sha_cache:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            self._sha_cache[key] = h.hexdigest()
        return self._sha_cache[key]

    def update_info(self):
        """อ่าน updates/latest.json → {"ok", "version", "notes", "url", "files": {plat: {name,size,sha256}}}"""
        meta_path = os.path.join(self.updates_dir, "latest.json") if self.updates_dir else ""
        if not meta_path or not os.path.isfile(meta_path):
            return {"ok": True, "version": None}
        try:
            with open(meta_path, encoding="utf-8") as f:
                meta = json.load(f)
        except Exception as e:
            return {"ok": False, "err": "latest.json ผิดรูปแบบ: %s" % e}
        files = {}
        for plat, name in (meta.get("files") or {}).items():
            path = os.path.join(self.updates_dir, os.path.basename(str(name)))
            if os.path.isfile(path):
                files[plat] = {"name": os.path.basename(path), "size": os.path.getsize(path), "sha256": self._sha256(path)}
        return {"ok": True, "version": str(meta.get("version", "")), "notes": str(meta.get("notes", ""))[:4000],
                "url": str(meta.get("url", "")), "files": files}

    UPDATE_EXT = (".exe", ".dmg", ".zip", ".pkg", ".msi", ".py", ".bin", ".appimage")

    def updates_view(self):
        d = self.updates_dir
        meta = {}
        try:
            with open(os.path.join(d, "latest.json"), encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            meta = {}
        files = []
        if d and os.path.isdir(d):
            for name in sorted(os.listdir(d)):
                path = os.path.join(d, name)
                if os.path.isfile(path) and name.lower().endswith(self.UPDATE_EXT):
                    st = os.stat(path)
                    files.append({"name": name, "size": st.st_size, "mtime": st.st_mtime})
        with self.lock:
            hosts = [{"id": hid, "name": hc.name, "app": hc.app} for hid, hc in self.hosts.items()]
        return {"dir": d, "latest": {"version": str(meta.get("version", "") or ""), "notes": str(meta.get("notes", "")),
                                     "url": str(meta.get("url", "")), "files": meta.get("files") or {}},
                "published": bool(meta.get("version")), "files": files, "hosts": hosts}

    def save_update_file(self, name, stream, length):
        name = os.path.basename(str(name or "")).strip()
        if not name or name.startswith(".") or not name.lower().endswith(self.UPDATE_EXT):
            raise ValueError("ext")
        if length <= 0 or length > 1024 ** 3:
            raise ValueError("size")
        os.makedirs(self.updates_dir, exist_ok=True)
        path = os.path.join(self.updates_dir, name)
        tmp = path + ".uploading"
        got = 0
        try:
            with open(tmp, "wb") as f:
                while got < length:
                    chunk = stream.read(min(262144, length - got))
                    if not chunk:
                        raise ConnectionError("cut")
                    f.write(chunk)
                    got += len(chunk)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        self._sha_cache.pop(path, None)
        return name

    def publish_update(self, d):
        version = str(d.get("version", "")).strip()
        if not re.match(r"^\d+(\.\d+){0,3}$", version):
            raise ValueError("version")
        files = {}
        for plat, name in (d.get("files") or {}).items():
            name = os.path.basename(str(name or ""))
            if not name:
                continue
            if plat not in ("windows", "mac-arm64", "mac-x86_64", "linux", "source"):
                raise ValueError("plat")
            if not os.path.isfile(os.path.join(self.updates_dir, name)):
                raise ValueError("file")
            files[plat] = name
        meta = {"version": version, "notes": str(d.get("notes", ""))[:4000], "url": str(d.get("url", ""))[:500],
                "files": files, "published": time.strftime("%Y-%m-%d %H:%M:%S")}
        os.makedirs(self.updates_dir, exist_ok=True)
        tmp = os.path.join(self.updates_dir, "latest.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
        os.replace(tmp, os.path.join(self.updates_dir, "latest.json"))
        self.event("info", "ผู้ดูแลเผยแพร่อัปเดตโปรแกรมเวอร์ชัน %s" % version)

    def unpublish_update(self):
        try:
            os.remove(os.path.join(self.updates_dir, "latest.json"))
            self.event("warn", "ผู้ดูแลหยุดแจกอัปเดตโปรแกรม")
        except OSError:
            pass

    def delete_update_file(self, name):
        name = os.path.basename(str(name or ""))
        if not name.lower().endswith(self.UPDATE_EXT):
            raise ValueError("ext")
        os.remove(os.path.join(self.updates_dir, name))

    def _send_update(self, conn, ip, plat):
        info = self.update_info()
        f = (info.get("files") or {}).get(plat)
        if not f:
            line_send(conn, {"ok": False, "err": "Server ไม่มีไฟล์อัปเดตสำหรับ %s" % (plat or "เครื่องนี้")})
            return
        line_send(conn, dict(f, ok=True, version=info.get("version")))
        self.event("info", "%s ดาวน์โหลดอัปเดต %s (%s)" % (ip, f["name"], info.get("version")))
        with open(os.path.join(self.updates_dir, f["name"]), "rb") as fh:
            for chunk in iter(lambda: fh.read(256 * 1024), b""):
                conn.sendall(chunk)

    # ----- สำหรับหน้าเว็บมอนิเตอร์ -----
    def snapshot(self):
        now = time.time()
        with self.lock:
            hosts = list(self.hosts.items())
            sessions = list(self.sessions.values())
        busy = defaultdict(int)
        out_s = []
        for s in sessions:
            busy[s["hid"]] += 1
            t0, u0, d0 = self.samples.get(s["sid"], (s["start"], 0, 0))
            dt = max(0.5, now - t0)
            ru, rd = (s["up"] - u0) / dt, (s["down"] - d0) / dt
            self.samples[s["sid"]] = (now, s["up"], s["down"])
            out_s.append({"sid": s["sid"], "client": s["client"], "hid": s["hid"], "hname": s["hname"],
                          "hip": s["hip"], "dur": now - s["start"], "up": s["up"], "down": s["down"],
                          "rate_up": ru, "rate_down": rd, "mode": s.get("mode", "relay"), "why": s.get("why", ""),
                          "how": s.get("how", "")})
        out_s.sort(key=lambda x: -x["dur"])
        out_h = [{"id": hid, "name": hc.name, "ip": hc.ip, "online": now - hc.since, "sessions": busy[hid],
                  "app": hc.app}
                 for hid, hc in sorted(hosts, key=lambda kv: kv[1].since)]
        live = sum(s["up"] + s["down"] for s in sessions)
        try:
            latest = self.update_info().get("version")
        except Exception:
            latest = None
        return {"version": VERSION, "uptime": now - self.started, "port": self.port, "hosts": out_h, "latest": latest,
                "sessions": out_s, "events": list(self.events)[:100],
                "stats": dict(self.stats, bytes_total=self.stats["bytes_total"] + live,
                              rate=sum(s["rate_up"] + s["rate_down"] for s in out_s),
                              registered=len(self.secrets))}

    def kick_session(self, sid):
        with self.lock:
            s = self.sessions.get(sid)
        if not s:
            return False
        if s.get("mode") == "direct":
            try:
                s["hc"].send({"cmd": "kick"})          # ข้อมูลไม่ผ่าน Relay → สั่งเครื่องปลายทางตัดเอง
            except Exception:
                pass
        for sock in s["socks"]:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.event("warn", "ผู้ดูแลตัดการเชื่อมต่อ %s → ID %s" % (s["client"], s["hid"]))
        return True

    def kick_host(self, hid):
        with self.lock:
            hc = self.hosts.get(hid)
            sids = [s["sid"] for s in self.sessions.values() if s["hid"] == hid]
        for sid in sids:
            self.kick_session(sid)
        if hc:
            try:
                hc.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.event("warn", "ผู้ดูแลตัดเครื่อง ID %s ออกจาก Relay (เครื่องจะเชื่อมต่อกลับเองภายหลัง)" % hid)
        return bool(hc)


def fmt_dur(sec):
    sec = int(sec)
    h, m, s = sec // 3600, sec % 3600 // 60, sec % 60
    return "%d:%02d:%02d" % (h, m, s) if h else "%d:%02d" % (m, s)


# ============================================================================
# หน้าเว็บมอนิเตอร์
# ============================================================================
DASHBOARD = r"""<!doctype html>
<html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetRemote Relay</title>
<style>
:root{--bg:#F3F4F8;--card:#fff;--border:#E3E6EE;--text:#1D2130;--muted:#6B7280;--subtle:#EEF0F6;--field:#fff;
--accent:#6D4AFF;--accent2:#5B3AE6;--sel:#ECE7FF;--ok:#15803D;--okbg:#E6F6EC;--warn:#B45309;--warnbg:#FFF3E0;
--danger:#DC2626;--dangerbg:#FDECEC;--side:#1E1B3A;--side2:#2A2650;--sidetext:#C9C4F2;--c1:#6D4AFF;--c2:#0EA5E9;--c3:#F59E0B;--c4:#10B981}
@media (prefers-color-scheme:dark){:root{--bg:#121419;--card:#1B1E26;--border:#2B303B;--text:#E8EAF0;--muted:#9AA3B2;
--subtle:#252A34;--field:#13161D;--accent:#8B6CFF;--accent2:#7A58FF;--sel:#352C5E;--ok:#4ADE80;--okbg:#14301F;--warn:#FBBF24;
--warnbg:#3A2B10;--danger:#F87171;--dangerbg:#3A1818;--side:#0E0D1C;--side2:#1D1A38;--sidetext:#B3ACE6;--c1:#8B6CFF;--c2:#38BDF8;--c3:#FBBF24;--c4:#34D399}}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans Thai","Sukhumvit Set",sans-serif}
.app{display:flex;min-height:100vh}
/* ---------- sidebar ---------- */
.side{width:236px;flex:none;background:var(--side);color:#fff;display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:11px;padding:20px 18px 18px}
.logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(145deg,#7B5CFF,#5B3AE6);display:grid;place-items:center;flex:none}
.brand b{font-size:15px;display:block;line-height:1.2}.brand small{color:var(--sidetext);font-size:11px}
.nav{padding:6px 10px;display:flex;flex-direction:column;gap:3px}
.nav a{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:10px;color:var(--sidetext);text-decoration:none;font-weight:600;font-size:13.5px}
.nav a:hover{background:var(--side2);color:#fff}
.nav a.on{background:linear-gradient(145deg,#7B5CFF,#5B3AE6);color:#fff;box-shadow:0 6px 16px rgba(91,58,230,.35)}
.nav svg{flex:none;opacity:.95}
.nav .badge{margin-left:auto;background:#F59E0B;color:#1F1300;font-size:10px;padding:1px 7px;border-radius:99px}
.side .sp{flex:1}
.sfoot{padding:14px 16px 18px;border-top:1px solid rgba(255,255,255,.08);font-size:12px;color:var(--sidetext)}
.sfoot .st{display:flex;align-items:center;gap:7px;margin-bottom:12px}
.sfoot .st i{width:8px;height:8px;border-radius:50%;background:#4ADE80;box-shadow:0 0 0 3px rgba(74,222,128,.18)}
.sbtns{display:flex;gap:6px}
.sbtn{flex:1;text-align:center;color:#fff;text-decoration:none;font-weight:600;font-size:12px;padding:7px 8px;border-radius:8px;background:var(--side2);cursor:pointer;border:0;font-family:inherit}
.sbtn:hover{background:#3A3470}
/* ---------- main ---------- */
main{flex:1;min-width:0;padding:22px 28px 40px}
.top{display:flex;align-items:flex-end;gap:12px;margin-bottom:18px;flex-wrap:wrap}
.top h1{margin:0;font-size:22px}.top .sub{color:var(--muted);font-size:12.5px}
.top .sp{flex:1}
.live{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:6px}
.live i{width:7px;height:7px;border-radius:50%;background:var(--ok)}
.page{display:none}.page.on{display:block}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:14px;margin-bottom:18px}
.stat{padding:15px 18px}.stat .k{color:var(--muted);font-size:12px;font-weight:600}
.stat .v{font-size:26px;font-weight:700;margin-top:2px;font-variant-numeric:tabular-nums}.stat .s{color:var(--muted);font-size:12px}
.grid{display:grid;grid-template-columns:1.25fr 1fr;gap:16px}
.card h2{font-size:15.5px;margin:0;padding:16px 18px 6px;display:flex;align-items:center;gap:8px}
.card h2 .n{background:var(--sel);color:var(--accent);font-size:12px;padding:1px 9px;border-radius:99px}
.hint{color:var(--muted);font-size:12px;padding:0 18px 10px}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{font-size:11px;color:var(--muted);text-align:left;background:var(--subtle);padding:8px 12px;font-weight:600;white-space:nowrap}
td{padding:10px 12px;border-top:1px solid var(--border);vertical-align:middle}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:600}
.pill{font-size:11px;font-weight:700;padding:2px 9px;border-radius:99px;white-space:nowrap}
.p-ok{background:var(--okbg);color:var(--ok)}.p-busy{background:var(--dangerbg);color:var(--danger)}.p-warn{background:var(--warnbg);color:var(--warn)}
.p-mute{background:var(--subtle);color:var(--muted)}
.arrow{color:var(--accent);font-weight:700;padding:0 6px}
.muted{color:var(--muted)}.small{font-size:12px}
.kick{border:0;border-radius:8px;padding:6px 12px;font:inherit;font-size:12px;font-weight:600;cursor:pointer;background:var(--dangerbg);color:var(--danger)}
.kick:hover{background:var(--danger);color:#fff}
.empty{padding:26px;text-align:center;color:var(--muted)}
.ev{display:flex;gap:10px;padding:8px 18px;border-top:1px solid var(--border);font-size:13px}
.ev time{color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;margin-top:7px;flex:none;background:var(--muted)}
.d-online,.d-connect{background:var(--ok)}.d-warn{background:var(--warn)}.d-info{background:var(--accent)}
.why{color:var(--warn);max-width:220px;white-space:normal;text-align:right;line-height:1.3;margin-top:2px;margin-left:auto}
.events{max-height:520px;overflow:auto;padding-bottom:6px}
.err{background:var(--dangerbg);color:var(--danger);padding:10px 14px;border-radius:10px;margin-bottom:14px;display:none}
/* ---------- monitor ---------- */
.mcards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:16px}
.mc{padding:16px 18px;display:flex;gap:14px;align-items:center}
.ring{width:66px;height:66px;flex:none;position:relative}
.ring svg{transform:rotate(-90deg)}
.ring b{position:absolute;inset:0;display:grid;place-items:center;font-size:14px;font-variant-numeric:tabular-nums}
.mc .k{color:var(--muted);font-size:12px;font-weight:700;letter-spacing:.02em}
.mc .v{font-size:19px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1.3}
.mc .s{color:var(--muted);font-size:12px}
.netv{display:flex;flex-direction:column;gap:2px}
.netv span{font-size:16px;font-weight:700;font-variant-numeric:tabular-nums}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
.chart{padding:0 0 10px}
.chart .head{display:flex;align-items:center;gap:14px;padding:16px 18px 4px;flex-wrap:wrap}
.chart .head h3{margin:0;font-size:14.5px;flex:1}
.leg{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.leg i{width:10px;height:3px;border-radius:2px}
.leg b{color:var(--text);font-variant-numeric:tabular-nums}
.chart svg{display:block;width:100%;height:170px}
.gl{stroke:var(--border);stroke-width:1}.gt{fill:var(--muted);font-size:10px}
.bar{height:8px;border-radius:99px;background:var(--subtle);overflow:hidden;min-width:120px}
.bar i{display:block;height:100%;border-radius:99px;background:var(--c1)}
.kv{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;padding:6px 18px 18px;font-size:13px}
.kv span:nth-child(odd){color:var(--muted)}
/* ---------- settings ---------- */
.sbar{display:flex;align-items:center;gap:10px;padding:14px 18px;flex-wrap:wrap;margin-bottom:16px}
.sbar .p{flex:1;min-width:220px;font-size:12.5px;color:var(--muted)}
.sbar code{background:var(--subtle);padding:2px 7px;border-radius:6px;color:var(--text);font-size:12px;word-break:break-all}
.btn{border:1px solid var(--border);background:var(--card);color:var(--text);border-radius:10px;padding:9px 15px;font:inherit;font-weight:600;font-size:13px;cursor:pointer;display:inline-flex;align-items:center;gap:7px}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn.pri{background:linear-gradient(145deg,var(--accent),var(--accent2));color:#fff;border:0}
.btn.pri:hover{filter:brightness(1.08);color:#fff}
.btn.dan{color:var(--danger)}.btn.dan:hover{border-color:var(--danger)}
.btn:disabled{opacity:.55;cursor:default}
.groups{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.group{padding:4px 0 8px}
.field{padding:12px 18px;border-top:1px solid var(--border)}
.field:first-of-type{border-top:0}
.flab{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.flab b{font-size:13px}.flab code{font-size:10.5px;color:var(--muted)}
.tag{font-size:10.5px;font-weight:700;padding:1px 8px;border-radius:99px}
.t-live{background:var(--okbg);color:var(--ok)}.t-rs{background:var(--warnbg);color:var(--warn)}.t-lock{background:var(--subtle);color:var(--muted)}
.inp{position:relative}
.inp input,.inp select{width:100%;height:40px;border:1.5px solid var(--border);border-radius:10px;background:var(--field);color:var(--text);
font:inherit;font-size:14px;padding:0 12px;outline:none}
.inp input:focus,.inp select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--sel)}
.inp input:disabled{opacity:.6}
.inp.sec input{padding-right:44px;font-family:ui-monospace,Menlo,Consolas,monospace}
.eye{position:absolute;right:5px;top:5px;width:30px;height:30px;border:0;border-radius:8px;background:transparent;color:var(--muted);cursor:pointer;display:grid;place-items:center}
.eye:hover{background:var(--subtle)}
.fhelp{font-size:12px;color:var(--muted);margin-top:5px}
.ferr{font-size:12px;color:var(--danger);margin-top:5px;display:none}
.field.bad input{border-color:var(--danger)}.field.bad .ferr{display:block}
.field.dirty input,.field.dirty select{border-color:var(--c3)}
.savebar{position:sticky;bottom:14px;margin-top:16px;display:flex;align-items:center;gap:12px;padding:12px 16px;
box-shadow:0 10px 30px rgba(20,10,60,.15);flex-wrap:wrap}
.savebar .msg{flex:1;font-size:13px;color:var(--muted);min-width:200px}
.banner{display:none;padding:12px 16px;border-radius:12px;background:var(--warnbg);color:var(--warn);margin-bottom:16px;font-size:13px;align-items:center;gap:10px;flex-wrap:wrap}
.banner.on{display:flex}.banner .sp{flex:1}
.toast{position:fixed;left:50%;top:18px;transform:translateX(-50%) translateY(-20px);background:#1D2130;color:#fff;padding:11px 18px;border-radius:12px;
font-size:13px;opacity:0;transition:.25s;pointer-events:none;z-index:9;max-width:90vw}
.toast.on{opacity:1;transform:translateX(-50%)}
.overlay{position:fixed;inset:0;background:rgba(10,8,30,.55);display:none;place-items:center;z-index:8}
.overlay.on{display:grid}.overlay .card{padding:26px 30px;text-align:center;max-width:380px}
.spin{width:34px;height:34px;border-radius:50%;border:3px solid var(--sel);border-top-color:var(--accent);animation:sp 1s linear infinite;margin:0 auto 14px}
@keyframes sp{to{transform:rotate(360deg)}}
/* ---------- responsive ---------- */
@media(max-width:1180px){.mcards{grid-template-columns:repeat(2,1fr)}}
@media(max-width:1020px){.grid,.charts,.groups{grid-template-columns:1fr}}
@media(max-width:820px){
 .app{flex-direction:column}
 .side{width:auto;height:auto;position:sticky;top:0;z-index:5;flex-direction:row;align-items:center;flex-wrap:wrap}
 .brand{padding:10px 14px;flex:1}.brand small{display:none}
 .nav{flex-direction:row;padding:0 8px 8px;overflow-x:auto;order:3;flex-basis:100%}.nav a{padding:8px 10px;white-space:nowrap}
 .side .sp{display:none}.sfoot{border:0;padding:8px 12px}.sfoot .st{display:none}.sbtn{white-space:nowrap;padding:6px 10px}
 main{padding:16px}
 .mcards{grid-template-columns:1fr}
}
</style></head><body>
<div class="app">
<aside class="side">
 <div class="brand"><div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/><path d="M7 10h3l2-3 2 6 2-3h1"/></svg></div>
  <div><b>NetRemote Relay</b><small id="side-ver">v—</small></div></div>
 <nav class="nav">
  <a href="#overview" data-p="overview"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg><span>ภาพรวม</span></a>
  <a href="#monitor" data-p="monitor"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3-8 4 16 3-8h4"/></svg><span>Server Monitor</span></a>
  <a href="#updates" data-p="updates"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/></svg><span>อัปเดตโปรแกรม</span><span class="badge" id="nav-upd" hidden></span></a>
  <a href="#settings" data-p="settings"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg><span>ตั้งค่า Server</span><span class="badge" id="nav-pending" hidden>!</span></a>
 </nav>
 <div class="sp"></div>
 <div class="sfoot">
  <div class="st"><i id="st-dot"></i><span id="st-txt">Relay ทำงานอยู่</span></div>
  <div class="sbtns"><button class="sbtn" id="lang">English</button><a class="sbtn" href="logout" __LOGOUT__>ออกจากระบบ</a></div>
 </div>
</aside>
<main>
 <div class="top"><div><h1 id="ptitle">ภาพรวม</h1><div class="sub" id="sub">กำลังโหลด…</div></div><div class="sp"></div>
  <div class="live"><i></i><span>อัปเดตอัตโนมัติ</span></div></div>
 <div class="err" id="err"></div>

 <!-- =============== ภาพรวม =============== -->
 <section class="page" id="p-overview">
  <div class="stats">
   <div class="card stat"><div class="k">เครื่องออนไลน์</div><div class="v" id="s-hosts">–</div><div class="s">พร้อมให้เชื่อมต่อ</div></div>
   <div class="card stat"><div class="k">กำลังเชื่อมต่ออยู่</div><div class="v" id="s-sess">–</div><div class="s">เซสชันรีโมท</div></div>
   <div class="card stat"><div class="k">ความเร็วรวมตอนนี้</div><div class="v" id="s-rate">–</div><div class="s">ผ่าน Relay</div></div>
   <div class="card stat"><div class="k">ข้อมูลรวม</div><div class="v" id="s-bytes">–</div><div class="s" id="s-total">–</div></div>
   <div class="card stat"><div class="k">Relay ทำงานมาแล้ว</div><div class="v" id="s-up">–</div><div class="s" id="s-port">–</div></div>
  </div>
  <div class="grid">
   <div>
    <div class="card" style="margin-bottom:16px"><h2>กำลังเชื่อมต่ออยู่ <span class="n" id="n-sess">0</span></h2>
     <div class="hint">ใครกำลังรีโมทเข้าเครื่องไหน — ข้อมูลเข้ารหัสต้นทางถึงปลายทาง Relay มองไม่เห็นเนื้อหา</div>
     <div class="tw"><table><thead><tr><th>ผู้ควบคุม (IP)</th><th></th><th>เครื่องปลายทาง</th><th style="text-align:right">เวลา</th>
     <th style="text-align:right">ข้อมูล</th><th style="text-align:right">ความเร็ว</th><th></th></tr></thead>
     <tbody id="t-sess"></tbody></table></div></div>
    <div class="card"><h2>เครื่องที่ออนไลน์ <span class="n" id="n-hosts">0</span></h2>
     <div class="hint">เครื่องที่เปิดโปรแกรม NetRemote และเชื่อมกับ Relay อยู่</div>
     <div class="tw"><table><thead><tr><th>ID</th><th>ชื่อเครื่อง</th><th>IP</th><th>เวอร์ชัน</th><th style="text-align:right">ออนไลน์มาแล้ว</th>
     <th>สถานะ</th><th></th></tr></thead><tbody id="t-hosts"></tbody></table></div></div>
   </div>
   <div class="card"><h2>เหตุการณ์ล่าสุด</h2><div class="events" id="events"></div></div>
  </div>
 </section>

 <!-- =============== Server Monitor =============== -->
 <section class="page" id="p-monitor">
  <div class="mcards">
   <div class="card mc"><div class="ring" id="r-cpu"></div><div><div class="k">CPU</div><div class="v" id="m-cpu">–</div><div class="s" id="m-cpu-s">–</div></div></div>
   <div class="card mc"><div class="ring" id="r-mem"></div><div><div class="k">RAM</div><div class="v" id="m-mem">–</div><div class="s" id="m-mem-s">–</div></div></div>
   <div class="card mc"><div class="ring" id="r-disk"></div><div><div class="k">HARDDISK</div><div class="v" id="m-disk">–</div><div class="s" id="m-disk-s">–</div></div></div>
   <div class="card mc"><div class="ring neticon"><svg width="66" height="66" viewBox="0 0 66 66"><circle cx="33" cy="33" r="31" fill="var(--okbg)"/><path d="M27 21v22m0 0-6-6m6 6 6-6M39 45V23m0 0-6 6m6-6 6 6" fill="none" stroke="var(--c4)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/></svg></div><div><div class="k">NETWORK</div><div class="netv"><span id="m-rx">↓ –</span><span id="m-tx">↑ –</span></div><div class="s" id="m-net-s">–</div></div></div>
  </div>
  <div class="charts">
   <div class="card chart"><div class="head"><h3>CPU &amp; RAM</h3>
    <span class="leg"><i style="background:var(--c1)"></i>CPU <b id="l-cpu">–</b></span>
    <span class="leg"><i style="background:var(--c2)"></i>RAM <b id="l-mem">–</b></span></div><svg id="c-cpu"></svg></div>
   <div class="card chart"><div class="head"><h3>Network</h3>
    <span class="leg"><i style="background:var(--c4)"></i><span>รับ</span> <b id="l-rx">–</b></span>
    <span class="leg"><i style="background:var(--c3)"></i><span>ส่ง</span> <b id="l-tx">–</b></span></div><svg id="c-net"></svg></div>
  </div>
  <div class="charts">
   <div class="card chart"><div class="head"><h3>ข้อมูลผ่าน Relay</h3>
    <span class="leg"><i style="background:var(--c1)"></i><span>ตอนนี้</span> <b id="l-relay">–</b></span></div><svg id="c-relay"></svg></div>
   <div class="card"><h2>HARDDISK</h2><div class="tw"><table><thead><tr><th>ไดรฟ์ / Mount</th><th>ใช้ไป</th><th style="text-align:right">ใช้ไป / ทั้งหมด</th></tr></thead>
    <tbody id="t-disk"></tbody></table></div></div>
  </div>
  <div class="card"><h2>ข้อมูลเครื่อง Server</h2><div class="kv" id="sysinfo"></div></div>
 </section>

 <!-- =============== อัปเดตโปรแกรม =============== -->
 <section class="page" id="p-updates">
  <div class="grid">
   <div>
    <div class="card" style="margin-bottom:16px"><h2>เวอร์ชันที่แจกอยู่ตอนนี้</h2>
     <div class="hint">โปรแกรม NetRemote ทุกเครื่องตรวจหาอัปเดตจาก Server ทุก 1 ชั่วโมง (และตอนเปิดโปรแกรม) แล้วดาวน์โหลด + ติดตั้งให้เอง</div>
     <div id="u-current" style="padding:4px 18px 18px"></div></div>
    <div class="card" style="margin-bottom:16px"><h2>เผยแพร่เวอร์ชันใหม่</h2>
     <div class="hint">1) อัปโหลดไฟล์ที่ Build แล้ว (จาก GitHub Actions หรือ Build เอง)  2) ใส่เลขเวอร์ชัน  3) กดเผยแพร่</div>
     <div class="field"><div class="flab"><b>เลขเวอร์ชัน</b><code>VERSION</code></div><div class="inp"><input id="u-ver" placeholder="1.4"></div>
      <div class="fhelp">ต้องตรงกับ VERSION ใน remote_desktop.py ของไฟล์ที่ Build — ต้องมากกว่าเวอร์ชันที่เครื่องต่าง ๆ ใช้อยู่</div></div>
     <div class="field"><div class="flab"><b>มีอะไรใหม่</b></div><div class="inp"><textarea id="u-notes" rows="3" style="width:100%;border:1.5px solid var(--border);border-radius:10px;background:var(--field);color:var(--text);font:inherit;padding:8px 12px;outline:none;resize:vertical" placeholder="• ..."></textarea></div></div>
     <div id="u-plats"></div>
     <div class="field" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><button class="btn pri" id="u-publish">⬆ <span>เผยแพร่อัปเดต</span></button><span class="muted small" id="u-msg"></span></div>
    </div>
   </div>
   <div>
    <div class="card" style="margin-bottom:16px"><h2>เวอร์ชันของเครื่องที่ออนไลน์</h2><div class="tw"><table><thead><tr><th>ID</th><th>ชื่อเครื่อง</th><th>เวอร์ชัน</th><th>สถานะ</th></tr></thead><tbody id="u-hosts"></tbody></table></div></div>
    <div class="card"><h2>ไฟล์ในโฟลเดอร์อัปเดต</h2><div class="hint mono" id="u-dir" style="font-weight:400;word-break:break-all"></div>
     <div class="tw"><table><thead><tr><th>ไฟล์</th><th style="text-align:right">ขนาด</th><th>วันที่</th><th></th></tr></thead><tbody id="u-files"></tbody></table></div></div>
   </div>
  </div>
 </section>

 <!-- =============== ตั้งค่า Server =============== -->
 <section class="page" id="p-settings">
  <div class="banner" id="rs-banner"><span>⚠</span><span id="rs-text">มีค่าที่ต้องรีสตาร์ต Relay จึงจะมีผล</span><span class="sp"></span>
   <button class="btn dan" id="b-restart2">↻ <span>รีสตาร์ต Relay ตอนนี้</span></button></div>
  <div class="card sbar"><div class="p"><span>ไฟล์ตั้งค่า</span>: <code id="envpath">–</code><br><span>แก้ไขไฟล์ .env โดยตรงแล้วกด "โหลดค่าใหม่" ได้ — ค่าที่ตั้งผ่าน command line จะถูกล็อก</span></div>
   <button class="btn" id="b-reload">⟳ <span>โหลดค่าใหม่จากไฟล์</span></button>
   <button class="btn dan" id="b-restart">↻ <span>รีสตาร์ต Relay</span></button></div>
  <div class="groups" id="groups"></div>
  <div class="card savebar"><div class="msg" id="savemsg">แก้ไขค่าแล้วกดบันทึก — ค่าที่ "มีผลทันที" ใช้ได้เลยไม่ต้องรีสตาร์ต</div>
   <button class="btn" id="b-revert">ยกเลิกการแก้ไข</button><button class="btn pri" id="b-save">บันทึก</button></div>
 </section>
</main>
</div>
<div class="toast" id="toast"></div>
<div class="overlay" id="ov"><div class="card"><div class="spin"></div><b id="ov-t">กำลังรีสตาร์ต Relay…</b><div class="muted small" id="ov-s" style="margin-top:6px"></div></div></div>
<script>
const LANG=(()=>{try{return localStorage.getItem("nr_lang")||"en"}catch(e){return "en"}})();
const EN={
"ภาพรวม":"Overview","ตั้งค่า Server":"Server Settings","Relay ทำงานอยู่":"Relay running","ออกจากระบบ":"Sign out",
"กำลังโหลด…":"Loading…","อัปเดตอัตโนมัติ":"Auto-refresh",
"เครื่องออนไลน์":"Computers online","พร้อมให้เชื่อมต่อ":"ready to connect","กำลังเชื่อมต่ออยู่":"Active sessions",
"เซสชันรีโมท":"remote sessions","ความเร็วรวมตอนนี้":"Total speed now","ผ่าน Relay":"via Relay","ข้อมูลรวม":"Total data",
"Relay ทำงานมาแล้ว":"Relay uptime",
"ใครกำลังรีโมทเข้าเครื่องไหน — ข้อมูลเข้ารหัสต้นทางถึงปลายทาง Relay มองไม่เห็นเนื้อหา":"Who is controlling which computer — data is end-to-end encrypted, the Relay cannot see the content",
"ผู้ควบคุม (IP)":"Controller (IP)","เครื่องปลายทาง":"Remote computer","เวลา":"Time","ข้อมูล":"Data","ความเร็ว":"Speed",
"เครื่องที่ออนไลน์":"Online computers","เครื่องที่เปิดโปรแกรม NetRemote และเชื่อมกับ Relay อยู่":"Computers running NetRemote and connected to the Relay",
"ชื่อเครื่อง":"Computer name","เวอร์ชัน":"Version","ออนไลน์มาแล้ว":"Online for","สถานะ":"Status","เหตุการณ์ล่าสุด":"Recent events",
"ตัดการเชื่อมต่อเซสชันนี้?":"End this session?","ตัดเครื่องนี้ออกจาก Relay? (เครื่องจะเชื่อมต่อกลับเองภายหลัง)":"Remove this computer from the Relay? (it will reconnect by itself later)",
"พอร์ต":"port","โปรแกรมเวอร์ชันล่าสุด":"latest app","ทั้งหมด":"total","เซสชัน":"sessions","ลงทะเบียน":"registered",
"สองเครื่องเชื่อมต่อกันตรง ข้อมูลไม่ผ่าน Relay":"The two computers are connected directly — data does not pass through the Relay",
"⚡ เชื่อมต่อตรง":"⚡ Direct","ตัดการเชื่อมต่อ":"Disconnect","ยังไม่มีใครเชื่อมต่อ":"No active sessions","ต้องอัปเดต":"Update needed",
"● กำลังถูกควบคุม":"● In use","● ว่าง":"● Idle","ตัดออก":"Remove","ยังไม่มีเครื่องออนไลน์":"No computers online",
"ยังไม่มีเหตุการณ์":"No events yet","เชื่อมต่อ Relay ไม่ได้":"Cannot reach the Relay","วัน":"d","ชม.":"h","นาที":"min","วินาที":"s",
"รับ":"In","ส่ง":"Out","ข้อมูลผ่าน Relay":"Relay traffic","ตอนนี้":"now","ไดรฟ์ / Mount":"Drive / Mount","ใช้ไป":"Used",
"ใช้ไป / ทั้งหมด":"Used / Total","ข้อมูลเครื่อง Server":"Server information","คอร์":"cores","ว่าง":"free",
"โฟลเดอร์ Relay":"Relay folder","ชื่อเครื่อง Server":"Hostname","ระบบปฏิบัติการ":"Operating system","เปิดเครื่องมาแล้ว":"System uptime",
"Load average":"Load average","หน่วยความจำของ Relay":"Relay process memory","Threads":"Threads","Python":"Python",
"ไม่มีข้อมูล":"n/a","รวมตั้งแต่เปิดเครื่อง":"since boot","ติดตั้ง psutil เพื่อข้อมูลที่แม่นยำขึ้น: pip install psutil":"Install psutil for more accurate data: pip install psutil",
"ใช้ psutil":"using psutil","10 นาทีล่าสุด":"last 10 minutes",
"มีค่าที่ต้องรีสตาร์ต Relay จึงจะมีผล":"Some changes need a Relay restart to take effect","รีสตาร์ต Relay ตอนนี้":"Restart Relay now",
"ไฟล์ตั้งค่า":"Settings file","แก้ไขไฟล์ .env โดยตรงแล้วกด \"โหลดค่าใหม่\" ได้ — ค่าที่ตั้งผ่าน command line จะถูกล็อก":"You can also edit the .env file directly and press \"Reload\" — values set on the command line are locked",
"โหลดค่าใหม่จากไฟล์":"Reload from file","รีสตาร์ต Relay":"Restart Relay",
"แก้ไขค่าแล้วกดบันทึก — ค่าที่ \"มีผลทันที\" ใช้ได้เลยไม่ต้องรีสตาร์ต":"Edit values and press Save — \"Applies instantly\" values take effect without a restart",
"ยกเลิกการแก้ไข":"Discard changes","บันทึก":"Save","กำลังรีสตาร์ต Relay…":"Restarting Relay…",
"การเชื่อมต่อของโปรแกรม NetRemote":"NetRemote connections","หน้าเว็บมอนิเตอร์":"Monitor web page","ไฟล์และโฟลเดอร์":"Files and folders",
"มีผลทันที":"Applies instantly","ต้องรีสตาร์ต":"Restart required","ตั้งจาก command line":"Set on command line","ตั้งจาก environment":"Set by environment",
"รอรีสตาร์ต":"Pending restart","ค่าเริ่มต้น":"Default",
"พอร์ต Relay":"Relay port","พอร์ตที่โปรแกรม NetRemote เชื่อมต่อเข้ามา (ต้องเปิดใน Firewall)":"Port NetRemote apps connect to (must be open in the firewall)",
"Server Key":"Server Key","รหัสที่โปรแกรม NetRemote ต้องใส่ให้ตรงจึงจะใช้ Server ได้ — ถ้าเปลี่ยน ทุกเครื่องต้องใส่ค่าใหม่":"The key NetRemote apps must match to use the Server — if you change it, every computer needs the new key",
"เซสชันพร้อมกันสูงสุด":"Max concurrent sessions","จำนวนการรีโมทพร้อมกันสูงสุด":"Maximum simultaneous remote sessions",
"ไฟล์เก็บ ID":"ID store file","ไฟล์เก็บ ID ที่ลงทะเบียนแล้ว":"File that stores registered IDs",
"โฟลเดอร์อัปเดตโปรแกรม":"Update folder","โฟลเดอร์ที่มี latest.json + ไฟล์ .dmg/.exe (เว้นว่าง = updates/ ข้างโปรแกรม)":"Folder with latest.json + .dmg/.exe files (blank = updates/ next to the program)",
"พอร์ตหน้าเว็บ":"Web port","พอร์ตหน้ามอนิเตอร์นี้ (0 = ปิดหน้าเว็บ)":"Port of this monitor page (0 = disable)",
"เปิดให้ใครดูหน้าเว็บ":"Who can open this page","127.0.0.1 = เฉพาะเครื่อง Server เท่านั้น · 0.0.0.0 = เครื่องอื่นในเครือข่ายเปิดได้ (ต้องเข้าสู่ระบบ)":"127.0.0.1 = this Server only · 0.0.0.0 = other computers on the network (sign-in required)",
"รหัสผ่านหน้าเว็บ (Admin Key)":"Web password (Admin Key)","รหัสเข้าสู่ระบบหน้านี้ — เว้นว่าง = ใช้ Server Key":"Password for this page — blank = use the Server Key",
"เฉพาะเครื่องนี้ (127.0.0.1)":"This Server only (127.0.0.1)","ทุกเครื่องในเครือข่าย (0.0.0.0)":"Any computer on the network (0.0.0.0)","กำหนดเอง":"Custom",
"บันทึกแล้ว":"Saved","มีผลทันที:":"Applied now:","ต้องรีสตาร์ต:":"Needs restart:","ไม่มีค่าที่เปลี่ยน":"Nothing changed",
"โหลดค่าใหม่แล้ว":"Reloaded","บันทึกไม่สำเร็จ":"Save failed","ตัวเลขไม่ถูกต้อง":"Not a valid number","พอร์ตต้องอยู่ระหว่าง 1–65535":"Port must be 1–65535",
"ต้องอยู่ระหว่าง 1–10000":"Must be between 1 and 10000","IP ไม่ถูกต้อง":"Invalid IP address","ค่าไม่ถูกต้อง":"Invalid value",
"เปิดให้เครื่องอื่นดูได้ ต้องตั้งรหัสผ่านหน้าเว็บหรือ Server Key":"When open to other computers, set a web password or Server Key",
"รีสตาร์ต Relay ตอนนี้?\n\nเครื่องที่ออนไลน์จะหลุดชั่วครู่แล้วเชื่อมต่อกลับเอง การรีโมทที่ผ่าน Relay จะถูกตัด":"Restart the Relay now?\n\nOnline computers will drop briefly and reconnect by themselves. Remote sessions via the Relay will be ended.",
"รอ Relay กลับมา…":"Waiting for the Relay…","หน้าเว็บย้ายไปพอร์ต":"The page moved to port","Relay กลับมาแล้ว":"Relay is back",
"มีการแก้ไขที่ยังไม่บันทึก":"You have unsaved changes",
"อัปเดตโปรแกรม":"App Updates","เวอร์ชันที่แจกอยู่ตอนนี้":"Currently published version",
"โปรแกรม NetRemote ทุกเครื่องตรวจหาอัปเดตจาก Server ทุก 1 ชั่วโมง (และตอนเปิดโปรแกรม) แล้วดาวน์โหลด + ติดตั้งให้เอง":"Every NetRemote app checks the Server for updates every hour (and at startup), then downloads and installs them automatically",
"เผยแพร่เวอร์ชันใหม่":"Publish a new version","1) อัปโหลดไฟล์ที่ Build แล้ว (จาก GitHub Actions หรือ Build เอง)  2) ใส่เลขเวอร์ชัน  3) กดเผยแพร่":"1) Upload the built files (from GitHub Actions or your own build)  2) Enter the version  3) Publish",
"เลขเวอร์ชัน":"Version","ต้องตรงกับ VERSION ใน remote_desktop.py ของไฟล์ที่ Build — ต้องมากกว่าเวอร์ชันที่เครื่องต่าง ๆ ใช้อยู่":"Must match VERSION in remote_desktop.py of the build — and be higher than what computers run now",
"มีอะไรใหม่":"What's new","เผยแพร่อัปเดต":"Publish update","เวอร์ชันของเครื่องที่ออนไลน์":"Versions of online computers",
"ไฟล์ในโฟลเดอร์อัปเดต":"Files in the update folder","ไฟล์":"File","ขนาด":"Size","วันที่":"Date","หยุดแจกอัปเดต":"Stop offering",
"ไม่พบไฟล์":"File missing","ไม่มี":"None","ยังไม่ได้แจกอัปเดต — เครื่องต่าง ๆ จะไม่ได้รับเวอร์ชันใหม่จนกว่าจะเผยแพร่":"Nothing published yet — computers won't get a new version until you publish one",
"เวอร์ชันเก่ามาก":"Very old version","รออัปเดต":"Update pending","ล่าสุด":"Up to date","ลบ":"Delete","ยังไม่มีไฟล์ — อัปโหลดด้านซ้าย":"No files yet — upload on the left",
"ไม่แจกสำหรับเครื่องแบบนี้":"not offered for this platform","อัปโหลด…":"Upload…","อัปโหลดแล้ว":"Uploaded","อัปโหลดไม่สำเร็จ":"Upload failed",
"ชนิดไฟล์ไม่รองรับ":"file type not supported","ใส่เลขเวอร์ชัน เช่น 1.4":"Enter a version, e.g. 1.4","เลือกไฟล์อย่างน้อย 1 แบบ":"Choose at least one file",
"เลขเวอร์ชันไม่มากกว่าเวอร์ชันที่แจกอยู่ — เครื่องที่อัปเดตไปแล้วจะไม่ได้รับไฟล์นี้ ต้องการเผยแพร่ต่อหรือไม่?":"This version is not higher than the published one — computers already updated won't get it. Publish anyway?",
"เผยแพร่เวอร์ชัน":"Published version","แล้ว — เครื่องต่าง ๆ จะอัปเดตภายใน 1 ชั่วโมง หรือเมื่อเปิดโปรแกรมใหม่":"— computers will update within an hour or when the app restarts",
"เผยแพร่ไม่สำเร็จ":"Publish failed","หยุดแจกอัปเดต? เครื่องต่าง ๆ จะไม่ได้รับเวอร์ชันนี้อีก (ไฟล์ยังอยู่)":"Stop offering this update? Computers won't receive it any more (files are kept)",
"ลบไฟล์":"Delete file",
"สองเครื่องต่อหากันตรงไม่ได้ (Firewall/Router)":"The two computers cannot reach each other (firewall/router)",
"เครื่องปลายทางใช้โปรแกรมเวอร์ชันเก่า":"The remote computer runs an old version",
"เครื่องปลายทางปิดการเชื่อมต่อตรง":"Direct connection is off on the remote computer",
"เครื่องที่ควบคุมใช้เวอร์ชันเก่าหรือปิดการเชื่อมต่อตรง":"The controlling computer runs an old version or has direct connection off","แสดง":"Show","ซ่อน":"Hide","ค่าในไฟล์ .env":"Value in .env file","กำลังใช้":"In use"
};
const t=s=>LANG==="en"?(EN[s]??s):s;
const WHYT={unreachable:"สองเครื่องต่อหากันตรงไม่ได้ (Firewall/Router)",host_old:"เครื่องปลายทางใช้โปรแกรมเวอร์ชันเก่า",
 host_off:"เครื่องปลายทางปิดการเชื่อมต่อตรง",client_off:"เครื่องที่ควบคุมใช้เวอร์ชันเก่าหรือปิดการเชื่อมต่อตรง"};
const LOC=LANG==="en"?"en-GB":"th-TH";
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fb=n=>{if(n==null||isNaN(n))return "–";n=+n;const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?n.toFixed(n<10?2:1):Math.round(n))+" "+u[i]};
const fd=s=>{s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),x=s%60;
 return d?`${d} ${t("วัน")} ${h} ${t("ชม.")}`:h?`${h}:${String(m).padStart(2,"0")}:${String(x).padStart(2,"0")}`:`${m}:${String(x).padStart(2,"0")}`};
const fid=i=>String(i).replace(/(\d{3})(\d{3})(\d{3})/,"$1 $2 $3");
const tm=x=>new Date(x*1000).toLocaleTimeString(LOC,{hour12:false});
const pct=v=>v==null?"–":(v<10?v.toFixed(1):Math.round(v))+"%";
function toast(m,ms){const e=$("toast");e.textContent=m;e.classList.add("on");clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove("on"),ms||3000)}
async function api(path,body){const r=await fetch(path,body?{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}:{cache:"no-store"});
 if(r.status===401){location.replace("login");throw new Error("login")}const d=await r.json().catch(()=>({}));d._status=r.status;return d}

/* ---------- i18n static ---------- */
(function(){if(LANG!=="en")return;const w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);let n;
 while((n=w.nextNode())){const k=n.nodeValue.trim();if(k&&EN[k])n.nodeValue=n.nodeValue.replace(k,EN[k])}document.documentElement.lang="en"})();
$("lang").textContent=LANG==="en"?"ไทย":"English";
$("lang").onclick=()=>{if(dirty()&&!confirm(t("มีการแก้ไขที่ยังไม่บันทึก")))return;try{localStorage.setItem("nr_lang",LANG==="en"?"th":"en")}catch(_){}location.reload()};

/* ---------- routing ---------- */
const PAGES={overview:"ภาพรวม",monitor:"Server Monitor",updates:"อัปเดตโปรแกรม",settings:"ตั้งค่า Server"};
let page="overview";
function go(){page=(location.hash||"#overview").slice(1);if(!PAGES[page])page="overview";
 document.querySelectorAll(".page").forEach(p=>p.classList.toggle("on",p.id==="p-"+page));
 document.querySelectorAll(".nav a").forEach(a=>a.classList.toggle("on",a.dataset.p===page));
 $("ptitle").textContent=t(PAGES[page]);document.title=t(PAGES[page])+" · NetRemote Relay";
 if(page==="monitor")loadSys();if(page==="settings")loadSettings();if(page==="updates")loadUpd()}
window.addEventListener("hashchange",go);

/* ---------- overview ---------- */
let STATE=null;
async function kick(kind,val){
 if(!confirm(kind==="sid"?t("ตัดการเชื่อมต่อเซสชันนี้?"):t("ตัดเครื่องนี้ออกจาก Relay? (เครื่องจะเชื่อมต่อกลับเองภายหลัง)")))return;
 await api("api/kick",{[kind]:val});load()}
async function load(){
 try{
  const d=await api("api/state");if(d._status!==200)throw new Error("HTTP "+d._status);STATE=d;$("err").style.display="none";
  $("st-dot").style.background="";$("st-txt").textContent=t("Relay ทำงานอยู่")+" · "+fd(d.uptime);
  $("side-ver").textContent="v"+d.version+" · "+t("พอร์ต")+" "+d.port;
  $("sub").textContent=`Relay v${d.version} · ${t("พอร์ต")} ${d.port} · ${t("โปรแกรมเวอร์ชันล่าสุด")} ${d.latest||"-"} · ${new Date().toLocaleTimeString(LOC,{hour12:false})}`;
  if(page!=="overview")return;
  $("s-hosts").textContent=d.hosts.length;$("s-sess").textContent=d.sessions.length;
  $("s-rate").textContent=fb(d.stats.rate)+"/s";$("s-bytes").textContent=fb(d.stats.bytes_total);
  $("s-total").textContent=`${t("ทั้งหมด")} ${d.stats.sessions_total} ${t("เซสชัน")} · ${t("ลงทะเบียน")} ${d.stats.registered} ID`;
  $("s-up").textContent=fd(d.uptime);$("s-port").textContent=`Relay v${d.version} · ${t("พอร์ต")} ${d.port}`;
  $("n-sess").textContent=d.sessions.length;$("n-hosts").textContent=d.hosts.length;
  $("t-sess").innerHTML=d.sessions.length?d.sessions.map(s=>`<tr>
   <td class="mono">${esc(s.client)}</td><td class="arrow">→</td>
   <td><b>${esc(s.hname||"-")}</b><div class="small muted mono" style="white-space:nowrap">ID ${fid(s.hid)}</div></td>
   <td class="num">${fd(s.dur)}</td>${s.mode==="direct"
    ?`<td class="num" colspan="2"><span class="pill p-ok" title="${t("สองเครื่องเชื่อมต่อกันตรง ข้อมูลไม่ผ่าน Relay")}">${t("⚡ เชื่อมต่อตรง")}</span></td>`
    :`<td class="num">${fb(s.up+s.down)}<div class="small muted">${t("ผ่าน Relay")}</div>${s.why?`<div class="small why">⚠ ${esc(t(WHYT[s.why]||s.why))}</div>`:""}</td>
   <td class="num">${fb(s.rate_up+s.rate_down)}/s<div class="small muted">↑${fb(s.rate_up)} ↓${fb(s.rate_down)}</div></td>`}
   <td class="num"><button class="kick" onclick="kick('sid','${s.sid}')">${t("ตัดการเชื่อมต่อ")}</button></td></tr>`).join("")
   :`<tr><td colspan="7" class="empty">${t("ยังไม่มีใครเชื่อมต่อ")}</td></tr>`;
  $("t-hosts").innerHTML=d.hosts.length?d.hosts.map(h=>`<tr>
   <td class="mono">${fid(h.id)}</td><td><b>${esc(h.name||"-")}</b></td><td class="mono small">${esc(h.ip)}</td>
   <td class="small">${esc(h.app||"-")}${d.latest&&h.app&&h.app!==d.latest?` <span class="pill p-warn">${t("ต้องอัปเดต")}</span>`:""}</td>
   <td class="num">${fd(h.online)}</td>
   <td>${h.sessions?`<span class="pill p-busy">${t("● กำลังถูกควบคุม")}</span>`:`<span class="pill p-ok">${t("● ว่าง")}</span>`}</td>
   <td class="num"><button class="kick" onclick="kick('host','${h.id}')">${t("ตัดออก")}</button></td></tr>`).join("")
   :`<tr><td colspan="7" class="empty">${t("ยังไม่มีเครื่องออนไลน์")}</td></tr>`;
  $("events").innerHTML=d.events.length?d.events.map(e=>`<div class="ev"><span class="dot d-${e.kind}"></span>
   <time>${tm(e.t)}</time><span>${esc(LANG==="en"&&e.en?e.en:e.text)}</span></div>`).join(""):`<div class="empty">${t("ยังไม่มีเหตุการณ์")}</div>`;
 }catch(e){if(e.message==="login")return;$("err").textContent=t("เชื่อมต่อ Relay ไม่ได้")+": "+e.message;$("err").style.display="block";
  $("st-dot").style.background="var(--danger)"}
}

/* ---------- monitor ---------- */
function ring(el,v,color){const r=28,c=2*Math.PI*r,p=v==null?0:Math.max(0,Math.min(100,v));
 const col=p>=90?"var(--danger)":p>=75?"var(--warn)":color;
 el.innerHTML=`<svg width="66" height="66" viewBox="0 0 66 66"><circle cx="33" cy="33" r="${r}" fill="none" stroke="var(--subtle)" stroke-width="7"/>
 <circle cx="33" cy="33" r="${r}" fill="none" stroke="${col}" stroke-width="7" stroke-linecap="round" stroke-dasharray="${c*p/100} ${c}" style="transition:stroke-dasharray .6s"/></svg><b>${v==null?"–":Math.round(p)+"%"}</b>`}
function chart(el,series,opt){
 const W=Math.max(320,el.clientWidth||600),H=170,L=46,R=10,T=12,B=22;el.setAttribute("viewBox",`0 0 ${W} ${H}`);
 const n=Math.max(2,...series.map(s=>s.data.length));let max=opt.max;
 if(!max){max=Math.max(opt.min||1,...series.flatMap(s=>s.data.filter(v=>v!=null)));const p=Math.pow(1024,Math.floor(Math.log(max)/Math.log(1024)));
  const steps=[1,2,4,5,8,10,16,20,25,32,40,50,64,80,100,128,160,200,256,320,400,500,512,640,800,1000,1024];max=p*(steps.find(x=>x*p>=max*1.1)||1024)}
 const x=i=>L+(W-L-R)*i/(n-1),y=v=>T+(H-T-B)*(1-Math.min(v,max)/max);
 let g="";for(let k=0;k<=3;k++){const v=max*k/3,yy=y(v);g+=`<line class="gl" x1="${L}" x2="${W-R}" y1="${yy}" y2="${yy}"/><text class="gt" x="${L-6}" y="${yy+3}" text-anchor="end">${opt.fmt(v)}</text>`}
 const span=Math.round((n-1)*(opt.step||2));
 g+=`<text class="gt" x="${L}" y="${H-5}">−${span<90?span+" "+t("วินาที"):Math.round(span/60)+" "+t("นาที")}</text><text class="gt" x="${W-R}" y="${H-5}" text-anchor="end">${t("ตอนนี้")}</text>`;
 let defs="",paths="";series.forEach((s,si)=>{const pts=[];const off=n-s.data.length;s.data.forEach((v,i)=>{if(v!=null)pts.push([x(i+off),y(v)])});
  if(pts.length<2)return;const line=pts.map((p,i)=>(i?"L":"M")+p[0].toFixed(1)+" "+p[1].toFixed(1)).join(" ");
  defs+=`<linearGradient id="g${el.id}${si}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="${s.color}" stop-opacity=".28"/><stop offset="1" stop-color="${s.color}" stop-opacity="0"/></linearGradient>`;
  paths+=`<path d="${line} L${pts[pts.length-1][0]} ${H-B} L${pts[0][0]} ${H-B}Z" fill="url(#g${el.id}${si})"/><path d="${line}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round"/>`});
 el.innerHTML=`<defs>${defs}</defs>${g}${paths}`}
const css=v=>getComputedStyle(document.documentElement).getPropertyValue(v).trim();
async function loadSys(){
 if(page!=="monitor")return;
 let d;try{d=await api("api/system")}catch(e){return}
 const h=d.hist||[],m=d.mem,info=d.info||{};
 ring($("r-cpu"),d.cpu,css("--c1"));$("m-cpu").textContent=pct(d.cpu);
 $("m-cpu-s").textContent=`${info.cores||"?"} ${t("คอร์")}`+(info.load?` · load ${info.load.map(x=>x.toFixed(2)).join(" ")}`:"");
 const mp=m&&m.total?100*m.used/m.total:null;ring($("r-mem"),mp,css("--c2"));
 $("m-mem").textContent=m?`${fb(m.used)}`:t("ไม่มีข้อมูล");$("m-mem-s").textContent=m?`/ ${fb(m.total)}`+(m.swap_total?` · swap ${fb(m.swap_used)}`:""):"–";
 const disks=d.disks||[],main=disks.find(x=>x.relay)||disks[0];
 if(main){const p=100*main.used/main.total;ring($("r-disk"),p,css("--c3"));$("m-disk").textContent=`${fb(main.total-main.used)} ${t("ว่าง")}`;
  $("m-disk-s").textContent=`${fb(main.used)} / ${fb(main.total)}`}else{ring($("r-disk"),null,css("--c3"));$("m-disk").textContent=t("ไม่มีข้อมูล")}
 $("m-rx").textContent="↓ "+(d.rx==null?t("ไม่มีข้อมูล"):fb(d.rx)+"/s");$("m-tx").textContent="↑ "+(d.tx==null?"–":fb(d.tx)+"/s");
 $("m-net-s").textContent=d.net_total?`${t("รวมตั้งแต่เปิดเครื่อง")} ↓${fb(d.net_total[0])} ↑${fb(d.net_total[1])}`:"–";
 $("l-cpu").textContent=pct(d.cpu);$("l-mem").textContent=pct(mp);$("l-rx").textContent=d.rx==null?"–":fb(d.rx)+"/s";
 $("l-tx").textContent=d.tx==null?"–":fb(d.tx)+"/s";$("l-relay").textContent=fb(d.relay_rate)+"/s";
 const step=d.interval||2;
 chart($("c-cpu"),[{data:h.map(p=>p.cpu),color:css("--c1")},{data:h.map(p=>p.mem),color:css("--c2")}],{max:100,fmt:v=>Math.round(v)+"%",step});
 chart($("c-net"),[{data:h.map(p=>p.rx),color:css("--c4")},{data:h.map(p=>p.tx),color:css("--c3")}],{fmt:v=>fb(v).replace(" ",""),step,min:1024});
 chart($("c-relay"),[{data:h.map(p=>p.relay),color:css("--c1")}],{fmt:v=>fb(v).replace(" ",""),step,min:1024});
 $("t-disk").innerHTML=disks.length?disks.map(x=>{const p=100*x.used/x.total;const col=p>=90?"var(--danger)":p>=75?"var(--warn)":"var(--c3)";
  return `<tr><td><b class="mono small">${esc(x.path)}</b>${x.relay?` <span class="pill p-mute">${t("โฟลเดอร์ Relay")}</span>`:""}</td>
  <td><div class="bar"><i style="width:${p.toFixed(1)}%;background:${col}"></i></div><div class="small muted">${p.toFixed(1)}%</div></td>
  <td class="num">${fb(x.used)} / ${fb(x.total)}</td></tr>`}).join(""):`<tr><td colspan="3" class="empty">${t("ไม่มีข้อมูล")}</td></tr>`;
 const kv=[["ชื่อเครื่อง Server",info.host],["ระบบปฏิบัติการ",info.os],["Python",info.python],["CPU",(info.cores||"?")+" "+t("คอร์")],
  ["เปิดเครื่องมาแล้ว",info.boot?fd(Date.now()/1000-info.boot):"–"],["Relay ทำงานมาแล้ว",STATE?fd(STATE.uptime):"–"],
  ["หน่วยความจำของ Relay",fb(info.rss)],["Threads",info.threads]];
 $("sysinfo").innerHTML=kv.map(([k,v])=>`<span>${t(k)}</span><span>${esc(v??"–")}</span>`).join("")+
  `<span></span><span class="small muted">${info.psutil?t("ใช้ psutil"):t("ติดตั้ง psutil เพื่อข้อมูลที่แม่นยำขึ้น: pip install psutil")} · ${t("10 นาทีล่าสุด")}</span>`;
}

/* ---------- updates ---------- */
const PLATS=[["windows","Windows","(.exe)"],["mac-arm64","macOS Apple Silicon","(.dmg)"],["mac-x86_64","macOS Intel","(.dmg)"],
 ["source","Source (remote_desktop.py)","(.py)"]];
let UPD=null;
const vt=v=>String(v||"0").split(".").map(x=>parseInt(x)||0);
const vcmp=(a,b)=>{a=vt(a);b=vt(b);for(let i=0;i<Math.max(a.length,b.length);i++){const d=(a[i]||0)-(b[i]||0);if(d)return d}return 0};
const extOk=(k,n)=>{n=n.toLowerCase();return k==="windows"?n.endsWith(".exe"):k==="source"?n.endsWith(".py"):(n.endsWith(".dmg")||n.endsWith(".zip"))};
async function loadUpd(keep){
 let d;try{d=await api("api/updates")}catch(e){return}UPD=d;const L=d.latest||{},files=d.files||[];
 const fmap=Object.fromEntries(files.map(f=>[f.name,f]));
 $("u-current").innerHTML=d.published?`<div style="display:flex;align-items:baseline;gap:12px;flex-wrap:wrap"><span style="font-size:30px;font-weight:800">v${esc(L.version)}</span>
  <button class="kick" onclick="unpublish()">${t("หยุดแจกอัปเดต")}</button></div>
  ${L.notes?`<div class="small" style="white-space:pre-wrap;margin:6px 0 10px">${esc(L.notes)}</div>`:""}
  <table><tbody>${PLATS.map(([k,n])=>{const f=L.files&&L.files[k];const ok=f&&fmap[f];
   return `<tr><td class="small"><b>${n}</b></td><td class="small mono">${f?esc(f):"–"}</td><td class="num small">${ok?fb(fmap[f].size):""}</td>
   <td>${f?(ok?`<span class="pill p-ok">✓</span>`:`<span class="pill p-busy">${t("ไม่พบไฟล์")}</span>`):`<span class="pill p-mute">${t("ไม่มี")}</span>`}</td></tr>`}).join("")}</tbody></table>`
  :`<div class="empty" style="padding:14px 0;text-align:left">${t("ยังไม่ได้แจกอัปเดต — เครื่องต่าง ๆ จะไม่ได้รับเวอร์ชันใหม่จนกว่าจะเผยแพร่")}</div>`;
 const hosts=d.hosts||[];
 $("u-hosts").innerHTML=hosts.length?hosts.map(h=>{const old=d.published&&h.app&&vcmp(h.app,L.version)<0,unk=!h.app;
  return `<tr><td class="mono small">${fid(h.id)}</td><td><b>${esc(h.name||"-")}</b></td><td class="small">${esc(h.app||"?")}</td>
  <td>${unk?`<span class="pill p-warn">${t("เวอร์ชันเก่ามาก")}</span>`:old?`<span class="pill p-warn">${t("รออัปเดต")}</span>`:`<span class="pill p-ok">${t("ล่าสุด")}</span>`}</td></tr>`}).join("")
  :`<tr><td colspan="4" class="empty">${t("ยังไม่มีเครื่องออนไลน์")}</td></tr>`;
 const pend=d.published?hosts.filter(h=>!h.app||vcmp(h.app,L.version)<0).length:0;
 $("nav-upd").hidden=!pend;$("nav-upd").textContent=pend;
 $("u-dir").textContent=d.dir||"";
 $("u-files").innerHTML=files.length?files.map(f=>`<tr><td class="mono small">${esc(f.name)}</td><td class="num small">${fb(f.size)}</td>
  <td class="small muted">${new Date(f.mtime*1000).toLocaleString(LOC,{hour12:false})}</td>
  <td class="num"><button class="kick" data-name="${esc(f.name)}" onclick="delFile(this.dataset.name)">${t("ลบ")}</button></td></tr>`).join("")
  :`<tr><td colspan="4" class="empty">${t("ยังไม่มีไฟล์ — อัปโหลดด้านซ้าย")}</td></tr>`;
 if(keep)return;
 const maxV=[L.version,...hosts.map(h=>h.app)].filter(Boolean).sort(vcmp).pop();
 if(maxV){const v=vt(maxV);v[v.length-1]++;$("u-ver").placeholder=v.join(".")}
 const cur={};document.querySelectorAll("#u-plats select").forEach(x=>cur[x.dataset.p]=x.value);
 $("u-plats").innerHTML=PLATS.map(([k,n,ext])=>{const want=cur[k]!==undefined?cur[k]:(L.files||{})[k];
  return `<div class="field"><div class="flab"><b>${n}</b><span class="muted small">${ext}</span></div>
  <div style="display:flex;gap:8px;align-items:center"><div class="inp" style="flex:1"><select data-p="${k}"><option value="">— ${t("ไม่แจกสำหรับเครื่องแบบนี้")} —</option>
  ${files.filter(f=>extOk(k,f.name)).map(f=>`<option ${want===f.name?"selected":""}>${esc(f.name)}</option>`).join("")}</select></div>
  <label class="btn" style="white-space:nowrap">⬆ ${t("อัปโหลด…")}<input type="file" hidden data-p="${k}" onchange="upload(this)"></label></div>
  <div class="bar" id="ub-${k}" style="margin-top:8px;display:none"><i style="width:0%"></i></div></div>`}).join("");
}
function upload(inp){
 const f=inp.files[0];if(!f)return;const k=inp.dataset.p,bar=$("ub-"+k);bar.style.display="block";
 const x=new XMLHttpRequest();x.open("POST","api/updates/upload?name="+encodeURIComponent(f.name));
 x.upload.onprogress=e=>{if(e.lengthComputable)bar.firstElementChild.style.width=(100*e.loaded/e.total).toFixed(1)+"%"};
 x.onload=async()=>{bar.style.display="none";let r={};try{r=JSON.parse(x.responseText)}catch(_){}
  if(x.status===200&&r.ok){toast("✓ "+t("อัปโหลดแล้ว")+": "+r.name);
   const vm=/(\d+\.\d+(?:\.\d+){0,2})/.exec(r.name);if(vm&&!$("u-ver").value.trim())$("u-ver").value=vm[1];
   const cur={};document.querySelectorAll("#u-plats select").forEach(s=>cur[s.dataset.p]=s.value);
   if(extOk(k,r.name))cur[k]=r.name;await loadUpd();
   document.querySelectorAll("#u-plats select").forEach(s=>{if(cur[s.dataset.p]!==undefined)s.value=cur[s.dataset.p]})}
  else toast("✗ "+t("อัปโหลดไม่สำเร็จ")+(r.err==="ext"?" — "+t("ชนิดไฟล์ไม่รองรับ"):""))};
 x.onerror=()=>{bar.style.display="none";toast("✗ "+t("อัปโหลดไม่สำเร็จ"))};x.send(f)}
$("u-publish").onclick=async()=>{
 const ver=($("u-ver").value.trim()||"");const files={};document.querySelectorAll("#u-plats select").forEach(s=>{if(s.value)files[s.dataset.p]=s.value});
 if(!/^\d+(\.\d+){0,3}$/.test(ver)){$("u-msg").textContent=t("ใส่เลขเวอร์ชัน เช่น 1.4");return}
 if(!Object.keys(files).length){$("u-msg").textContent=t("เลือกไฟล์อย่างน้อย 1 แบบ");return}
 if(UPD&&UPD.published&&vcmp(ver,UPD.latest.version)<=0&&!confirm(t("เลขเวอร์ชันไม่มากกว่าเวอร์ชันที่แจกอยู่ — เครื่องที่อัปเดตไปแล้วจะไม่ได้รับไฟล์นี้ ต้องการเผยแพร่ต่อหรือไม่?")))return;
 const r=await api("api/updates/publish",{version:ver,notes:$("u-notes").value,files});
 if(r.ok){toast("✓ "+t("เผยแพร่เวอร์ชัน")+" "+ver+" "+t("แล้ว — เครื่องต่าง ๆ จะอัปเดตภายใน 1 ชั่วโมง หรือเมื่อเปิดโปรแกรมใหม่"),6000);
  $("u-ver").value="";$("u-notes").value="";$("u-msg").textContent="";loadUpd()}
 else $("u-msg").textContent="✗ "+t("เผยแพร่ไม่สำเร็จ")+" ("+(r.err||"")+")"};
async function unpublish(){if(!confirm(t("หยุดแจกอัปเดต? เครื่องต่าง ๆ จะไม่ได้รับเวอร์ชันนี้อีก (ไฟล์ยังอยู่)")))return;await api("api/updates/unpublish",{});loadUpd()}
async function delFile(n){if(!confirm(t("ลบไฟล์")+" "+n+"?"))return;const r=await api("api/updates/delete",{name:n});if(!r.ok)toast("✗ "+(r.err||""));loadUpd()}

/* ---------- settings ---------- */
const FIELDS={
 RELAY_PORT:{g:0,label:"พอร์ต Relay",help:"พอร์ตที่โปรแกรม NetRemote เชื่อมต่อเข้ามา (ต้องเปิดใน Firewall)"},
 RELAY_KEY:{g:0,label:"Server Key",help:"รหัสที่โปรแกรม NetRemote ต้องใส่ให้ตรงจึงจะใช้ Server ได้ — ถ้าเปลี่ยน ทุกเครื่องต้องใส่ค่าใหม่"},
 RELAY_MAX_SESSIONS:{g:0,label:"เซสชันพร้อมกันสูงสุด",help:"จำนวนการรีโมทพร้อมกันสูงสุด"},
 RELAY_WEB_PORT:{g:1,label:"พอร์ตหน้าเว็บ",help:"พอร์ตหน้ามอนิเตอร์นี้ (0 = ปิดหน้าเว็บ)"},
 RELAY_WEB_BIND:{g:1,label:"เปิดให้ใครดูหน้าเว็บ",help:"127.0.0.1 = เฉพาะเครื่อง Server เท่านั้น · 0.0.0.0 = เครื่องอื่นในเครือข่ายเปิดได้ (ต้องเข้าสู่ระบบ)"},
 RELAY_ADMIN_KEY:{g:1,label:"รหัสผ่านหน้าเว็บ (Admin Key)",help:"รหัสเข้าสู่ระบบหน้านี้ — เว้นว่าง = ใช้ Server Key"},
 RELAY_STORE:{g:2,label:"ไฟล์เก็บ ID",help:"ไฟล์เก็บ ID ที่ลงทะเบียนแล้ว"},
 RELAY_UPDATES_DIR:{g:2,label:"โฟลเดอร์อัปเดตโปรแกรม",help:"โฟลเดอร์ที่มี latest.json + ไฟล์ .dmg/.exe (เว้นว่าง = updates/ ข้างโปรแกรม)"}};
const GROUPS=["การเชื่อมต่อของโปรแกรม NetRemote","หน้าเว็บมอนิเตอร์","ไฟล์และโฟลเดอร์"];
const ERRS={int:"ตัวเลขไม่ถูกต้อง",port:"พอร์ตต้องอยู่ระหว่าง 1–65535",range:"ต้องอยู่ระหว่าง 1–10000",ip:"IP ไม่ถูกต้อง",bad:"ค่าไม่ถูกต้อง",
 need_admin:"เปิดให้เครื่องอื่นดูได้ ต้องตั้งรหัสผ่านหน้าเว็บหรือ Server Key"};
let SET=null;
const EYE='<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>';
function dirty(){return SET?SET.items.some(i=>{const el=$("f-"+i.key);return el&&el.value!==i.value}):false}
function markDirty(){if(!SET)return;SET.items.forEach(i=>{const el=$("f-"+i.key);if(el)el.closest(".field").classList.toggle("dirty",el.value!==i.value)})}
async function loadSettings(force){
 if(SET&&dirty()&&!force)return;
 let d;try{d=await api("api/settings")}catch(e){return}
 SET=d;$("envpath").textContent=d.env_path+(d.env_exists?"":" (—)");
 $("groups").innerHTML=GROUPS.map((g,gi)=>`<div class="card group"><h2>${t(g)}</h2>`+d.items.filter(i=>FIELDS[i.key].g===gi).map(i=>{
  const f=FIELDS[i.key];const tags=[i.locked?`<span class="tag t-lock">🔒 ${t(i.source==="cli"?"ตั้งจาก command line":"ตั้งจาก environment")}</span>`:"",
   i.live?`<span class="tag t-live">${t("มีผลทันที")}</span>`:`<span class="tag t-rs">${t("ต้องรีสตาร์ต")}</span>`,
   i.pending?`<span class="tag t-rs">● ${t("รอรีสตาร์ต")} (${t("กำลังใช้")}: ${esc(i.running)})</span>`:""].join(" ");
  let input;
  if(i.key==="RELAY_WEB_BIND"){const opts=[["127.0.0.1","เฉพาะเครื่องนี้ (127.0.0.1)"],["0.0.0.0","ทุกเครื่องในเครือข่าย (0.0.0.0)"]];
   if(!opts.some(o=>o[0]===i.value))opts.push([i.value,t("กำหนดเอง")+": "+i.value]);
   input=`<div class="inp"><select id="f-${i.key}" ${i.locked?"disabled":""}>${opts.map(o=>`<option value="${esc(o[0])}" ${o[0]===i.value?"selected":""}>${esc(t(o[1]))}</option>`).join("")}</select></div>`}
  else if(i.type==="secret")input=`<div class="inp sec"><input id="f-${i.key}" type="password" autocomplete="off" value="${esc(i.value)}" ${i.locked?"disabled":""}>
   <button type="button" class="eye" title="${t("แสดง")}" onclick="const x=$('f-${i.key}');x.type=x.type==='password'?'text':'password'">${EYE}</button></div>`;
  else input=`<div class="inp"><input id="f-${i.key}" ${i.type==="int"?'inputmode="numeric"':""} value="${esc(i.value)}" placeholder="${esc(i.default)}" ${i.locked?"disabled":""}></div>`;
  return `<div class="field" id="w-${i.key}"><div class="flab"><b>${t(f.label)}</b><code>${i.key}</code>${tags}</div>${input}
   <div class="fhelp">${t(f.help)}</div><div class="ferr" id="e-${i.key}"></div></div>`}).join("")+`</div>`).join("");
 document.querySelectorAll("#groups input,#groups select").forEach(el=>el.addEventListener("input",markDirty));
 $("rs-banner").classList.toggle("on",d.pending.length>0);$("nav-pending").hidden=!d.pending.length;
}
function collect(){const v={};SET.items.forEach(i=>{const el=$("f-"+i.key);if(el&&!el.disabled&&el.value!==i.value)v[i.key]=el.value});return v}
function report(r,okWord){
 const parts=[];if(r.changed&&r.changed.length)parts.push(t("มีผลทันที:")+" "+r.changed.join(", "));
 if(r.pending&&r.pending.length)parts.push(t("ต้องรีสตาร์ต:")+" "+r.pending.join(", "));
 toast("✓ "+t(okWord)+(parts.length?" — "+parts.join(" · "):""),4500)}
$("b-save").onclick=async()=>{
 if(!SET)return;const vals=collect();document.querySelectorAll(".field").forEach(f=>f.classList.remove("bad"));
 if(!Object.keys(vals).length){toast(t("ไม่มีค่าที่เปลี่ยน"));return}
 $("b-save").disabled=true;
 try{const r=await api("api/settings",{values:vals});
  if(!r.ok){Object.entries(r.errors||{}).forEach(([k,e])=>{const w=$("w-"+k);if(w){w.classList.add("bad");$("e-"+k).textContent=t(ERRS[e]||"ค่าไม่ถูกต้อง")}});
   toast("✗ "+t("บันทึกไม่สำเร็จ")+(r.err?": "+r.err:""));return}
  await loadSettings(true);report(r,"บันทึกแล้ว");
 }finally{$("b-save").disabled=false}};
$("b-revert").onclick=()=>loadSettings(true);
$("b-reload").onclick=async()=>{if(dirty()&&!confirm(t("มีการแก้ไขที่ยังไม่บันทึก")))return;const r=await api("api/reload",{});await loadSettings(true);report(r,"โหลดค่าใหม่แล้ว")};
async function restart(){
 if(!confirm(t("รีสตาร์ต Relay ตอนนี้?\n\nเครื่องที่ออนไลน์จะหลุดชั่วครู่แล้วเชื่อมต่อกลับเอง การรีโมทที่ผ่าน Relay จะถูกตัด")))return;
 const r=await api("api/restart",{});$("ov").classList.add("on");$("ov-s").textContent=t("รอ Relay กลับมา…");
 const newPort=String(r.web_port||location.port||""),samePort=!newPort||newPort===(location.port||(location.protocol==="https:"?"443":"80"));
 const base=samePort?"":`${location.protocol}//${location.hostname}:${newPort}${location.pathname}`;
 if(!samePort)$("ov-s").textContent=t("หน้าเว็บย้ายไปพอร์ต")+" "+newPort+" …";
 await new Promise(r=>setTimeout(r,1800));
 for(let i=0;i<40;i++){try{const x=await fetch((base||"")+"api/state",samePort?{cache:"no-store"}:{cache:"no-store",mode:"no-cors"});if(!samePort||x.status===200||x.status===401){toast(t("Relay กลับมาแล้ว"));
  setTimeout(()=>location.href=(base||location.pathname)+"#settings",600);if(samePort)setTimeout(()=>location.reload(),700);return}}catch(e){}
  await new Promise(r=>setTimeout(r,1000))}
 if(!samePort)location.href=base+"#settings";else location.reload()}
$("b-restart").onclick=restart;$("b-restart2").onclick=restart;
window.addEventListener("beforeunload",e=>{if(dirty()){e.preventDefault();e.returnValue=""}});

go();load();setInterval(load,2000);setInterval(loadSys,2000);
setInterval(()=>{if(page==="settings")loadSettings();if(page==="updates")loadUpd(true)},15000);
api("api/settings").then(d=>{$("nav-pending").hidden=!(d.pending&&d.pending.length)}).catch(()=>{});
loadUpd(true);
</script></body></html>"""


LOGIN_PAGE = r"""<!doctype html>
<html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>เข้าสู่ระบบ · NetRemote Relay</title>
<style>
:root{--bg1:#6D4AFF;--bg2:#2E1A9E;--card:#fff;--text:#1D2130;--muted:#6B7280;--border:#E3E6EE;--field:#F6F7FB;
--accent:#6D4AFF;--accent2:#5B3AE6;--ring:rgba(109,74,255,.22);--danger:#DC2626;--dangerbg:#FDECEC}
@media (prefers-color-scheme:dark){:root{--bg1:#2A1D78;--bg2:#0E0B24;--card:#1B1E26;--text:#E8EAF0;--muted:#9AA3B2;
--border:#2B303B;--field:#13161D;--accent:#8B6CFF;--accent2:#7A58FF;--ring:rgba(139,108,255,.3);--danger:#F87171;--dangerbg:#3A1818}}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans Thai","Sukhumvit Set",sans-serif;
background:radial-gradient(1200px 600px at 15% -10%,rgba(255,255,255,.16),transparent 60%),
linear-gradient(145deg,var(--bg1),var(--bg2));display:grid;place-items:center;padding:16px;overflow:hidden}
.grid{position:fixed;inset:0;pointer-events:none;opacity:.12;
background-image:linear-gradient(rgba(255,255,255,.5) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.5) 1px,transparent 1px);
background-size:44px 44px;mask-image:radial-gradient(circle at 50% 40%,#000 0,transparent 70%)}
.wrap{position:relative;width:100%;max-width:400px}
.card{background:var(--card);border-radius:20px;padding:34px 30px 26px;box-shadow:0 30px 80px rgba(10,5,40,.45)}
.logo{width:58px;height:58px;border-radius:16px;margin:0 auto 16px;display:grid;place-items:center;
background:linear-gradient(145deg,var(--accent),var(--accent2));box-shadow:0 10px 24px var(--ring)}
h1{font-size:21px;text-align:center;margin:0}
.sub{color:var(--muted);text-align:center;margin:4px 0 24px;font-size:13px}
label{display:block;font-size:12px;font-weight:600;color:var(--muted);margin-bottom:6px}
.field{position:relative}
input[type=password],input[type=text]{width:100%;height:46px;border-radius:12px;border:1.5px solid var(--border);
background:var(--field);color:var(--text);font:inherit;font-size:15px;padding:0 46px 0 42px;outline:none;transition:.15s}
input:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--ring);background:var(--card)}
.ico{position:absolute;left:14px;top:13px;color:var(--muted)}
.eye{position:absolute;right:6px;top:6px;width:34px;height:34px;border:0;border-radius:9px;background:transparent;
color:var(--muted);cursor:pointer;display:grid;place-items:center}.eye:hover{background:var(--border);color:var(--text)}
.row{display:flex;align-items:center;justify-content:space-between;margin:14px 0 20px;font-size:13px}
.chk{display:flex;align-items:center;gap:8px;cursor:pointer;user-select:none}
.chk input{width:16px;height:16px;accent-color:var(--accent);margin:0}
.caps{color:#B45309;font-size:12px;display:none}
.go{width:100%;height:46px;border:0;border-radius:12px;font:inherit;font-size:15px;font-weight:700;color:#fff;cursor:pointer;
background:linear-gradient(145deg,var(--accent),var(--accent2));box-shadow:0 8px 20px var(--ring);transition:.15s}
.go:hover{filter:brightness(1.07)}.go:disabled{opacity:.6;cursor:default}
.err{display:none;background:var(--dangerbg);color:var(--danger);border-radius:10px;padding:10px 12px;font-size:13px;margin-bottom:14px}
.shake{animation:sh .35s}@keyframes sh{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
.foot{color:rgba(255,255,255,.75);text-align:center;font-size:12px;margin-top:16px}
.note{color:var(--muted);font-size:12px;text-align:center;margin-top:18px;border-top:1px solid var(--border);padding-top:14px}
.lang{position:absolute;top:14px;right:14px;font-size:12px;font-weight:600;color:var(--muted);text-decoration:none;
padding:4px 11px;border:1px solid var(--border);border-radius:99px}.lang:hover{color:var(--accent);border-color:var(--accent)}
form.card{position:relative}
</style></head><body><div class="grid"></div>
<div class="wrap"><form class="card" id="f" autocomplete="on"><a href="#" class="lang" id="lang">English</a>
  <div class="logo"><svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/><path d="M7 10h3l2-3 2 6 2-3h1"/></svg></div>
  <h1>NetRemote Relay</h1>
  <div class="sub">เข้าสู่ระบบหน้ามอนิเตอร์สำหรับผู้ดูแล</div>
  <div class="err" id="err"></div>
  <input type="text" name="username" value="admin" autocomplete="username" hidden>
  <label for="pw">รหัสผ่านผู้ดูแล (Admin Key)</label>
  <div class="field">
    <svg class="ico" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
    <input id="pw" type="password" autocomplete="current-password" placeholder="ใส่รหัสผ่าน" autofocus required>
    <button type="button" class="eye" id="eye" title="แสดงรหัสผ่าน" aria-label="แสดงรหัสผ่าน">
      <svg id="eyei" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>
    </button>
  </div>
  <div class="row">
    <label class="chk" style="margin:0;font-weight:500;color:var(--text);font-size:13px"><input type="checkbox" id="rem">จดจำการเข้าสู่ระบบ 30 วัน</label>
    <span class="caps" id="caps">⇪ Caps Lock เปิดอยู่</span>
  </div>
  <button class="go" id="go">เข้าสู่ระบบ</button>
  <div class="note"><span>รหัสผ่านคือ</span> <b>RELAY_ADMIN_KEY</b> <span>ในไฟล์ Server/.env</span><br><span>(ถ้าไม่ได้ตั้ง ใช้ค่าเดียวกับ RELAY_KEY)</span></div>
</form>
<div class="foot">NetRemote Relay v__VER__</div></div>
<script>
const LANG=(()=>{try{return localStorage.getItem("nr_lang")||"en"}catch(e){return "en"}})();
const EN={"เข้าสู่ระบบ · NetRemote Relay":"Sign in · NetRemote Relay","เข้าสู่ระบบหน้ามอนิเตอร์สำหรับผู้ดูแล":"Sign in to the admin monitor",
"รหัสผ่านผู้ดูแล (Admin Key)":"Admin password (Admin Key)","ใส่รหัสผ่าน":"Enter password","แสดงรหัสผ่าน":"Show password",
"จดจำการเข้าสู่ระบบ 30 วัน":"Keep me signed in for 30 days","⇪ Caps Lock เปิดอยู่":"⇪ Caps Lock is on","เข้าสู่ระบบ":"Sign in",
"รหัสผ่านคือ":"The password is","ในไฟล์ Server/.env":"in Server/.env","(ถ้าไม่ได้ตั้ง ใช้ค่าเดียวกับ RELAY_KEY)":"(if not set, the same as RELAY_KEY)",
"กำลังตรวจสอบ…":"Checking…","✓ สำเร็จ":"✓ Success","รหัสผ่านไม่ถูกต้อง":"Incorrect password","เชื่อมต่อ Relay ไม่ได้":"Cannot reach the Relay"};
const t=s=>LANG==="en"?(EN[s]??s):s;
const $=id=>document.getElementById(id), pw=$("pw");
if(LANG==="en"){const w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);let n;
 while((n=w.nextNode())){const k=n.nodeValue.trim();if(k&&EN[k])n.nodeValue=n.nodeValue.replace(k,EN[k])}
 document.querySelectorAll("[placeholder],[title],[aria-label]").forEach(el=>["placeholder","title","aria-label"].forEach(a=>{
  const v=el.getAttribute(a);if(v&&EN[v])el.setAttribute(a,EN[v])}));document.title=t(document.title);document.documentElement.lang="en"}
$("lang").textContent=LANG==="en"?"ไทย":"English";
$("lang").onclick=e=>{e.preventDefault();try{localStorage.setItem("nr_lang",LANG==="en"?"th":"en")}catch(_){}location.reload()};
$("eye").onclick=()=>{const t=pw.type==="password";pw.type=t?"text":"password";
 $("eyei").innerHTML=t?'<path d="M17.94 17.94A10.07 10.07 0 0 1 12 19c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19M1 1l22 22"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/>':'<path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>';pw.focus()};
pw.addEventListener("keyup",e=>{$("caps").style.display=e.getModifierState&&e.getModifierState("CapsLock")?"inline":"none"});
function fail(m){const e=$("err");e.textContent=m;e.style.display="block";const c=$("f");c.classList.remove("shake");void c.offsetWidth;c.classList.add("shake");pw.select()}
$("f").onsubmit=async ev=>{ev.preventDefault();const b=$("go");b.disabled=true;b.textContent=t("กำลังตรวจสอบ…");
 try{const r=await fetch("login",{method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({password:pw.value,remember:$("rem").checked,lang:LANG})});const d=await r.json();
   if(d.ok){b.textContent=t("✓ สำเร็จ");location.replace("./");return}
   fail(d.err||t("รหัสผ่านไม่ถูกต้อง"))}catch(e){fail(t("เชื่อมต่อ Relay ไม่ได้"))}
 b.disabled=false;b.textContent=t("เข้าสู่ระบบ")};
</script></body></html>"""


# ============================================================================
# Server Monitor — CPU / RAM / Disk / Network ของเครื่องที่รัน Relay
# ใช้ psutil ถ้ามี ไม่มีก็อ่านจากระบบเอง (Linux /proc, macOS sysctl/vm_stat/netstat, Windows API)
# ============================================================================
try:
    import psutil                                  # ไม่บังคับ
except Exception:
    psutil = None


def _run(cmd):
    try:
        import subprocess
        return subprocess.run(cmd, capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return ""


class SysMon(threading.Thread):
    def __init__(self, relay, interval=2.0, keep=300):
        super().__init__(daemon=True)
        self.relay, self.interval = relay, interval
        self.hist = deque(maxlen=keep)                # ~10 นาที
        self.cur = {}
        self.lock = threading.Lock()
        self.ncpu = os.cpu_count() or 1

    # ----- CPU -----
    def _cpu_times(self):
        if psutil:
            return None
        if sys.platform.startswith("linux"):
            try:
                with open("/proc/stat") as f:
                    v = [int(x) for x in f.readline().split()[1:]]
                idle = v[3] + (v[4] if len(v) > 4 else 0)
                return sum(v[:8]) - idle, sum(v[:8])
            except Exception:
                return None
        if os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes
                i, k, u = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
                ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
                f = lambda t: (t.dwHighDateTime << 32) | t.dwLowDateTime
                return f(k) + f(u) - f(i), f(k) + f(u)
            except Exception:
                return None
        return None

    def _cpu_percent(self, prev, now):
        if psutil:
            return psutil.cpu_percent(None)
        if prev and now and now[1] > prev[1]:
            return max(0.0, min(100.0, 100.0 * (now[0] - prev[0]) / (now[1] - prev[1])))
        if sys.platform == "darwin":
            try:
                tot = sum(float(x) for x in _run(["ps", "-A", "-o", "%cpu="]).split())
                return max(0.0, min(100.0, tot / self.ncpu))
            except Exception:
                return None
        return None

    # ----- RAM -----
    def _mem(self):
        if psutil:
            m, s = psutil.virtual_memory(), psutil.swap_memory()
            return {"total": m.total, "used": m.total - m.available, "swap_total": s.total, "swap_used": s.used}
        if sys.platform.startswith("linux"):
            try:
                d = {}
                with open("/proc/meminfo") as f:
                    for line in f:
                        k, v = line.split(":", 1)
                        d[k] = int(v.split()[0]) * 1024
                avail = d.get("MemAvailable", d.get("MemFree", 0))
                return {"total": d["MemTotal"], "used": d["MemTotal"] - avail,
                        "swap_total": d.get("SwapTotal", 0), "swap_used": d.get("SwapTotal", 0) - d.get("SwapFree", 0)}
            except Exception:
                return None
        if sys.platform == "darwin":
            try:
                total = int(_run(["sysctl", "-n", "hw.memsize"]).strip())
                vm = _run(["vm_stat"])
                ps = int(re.search(r"page size of (\d+)", vm).group(1))
                pg = lambda name: int(re.search(name + r":\s+(\d+)", vm).group(1)) if re.search(name + r":\s+(\d+)", vm) else 0
                used = (pg("Pages active") + pg("Pages wired down") + pg("Pages occupied by compressor")) * ps
                sw = _run(["sysctl", "-n", "vm.swapusage"])
                unit = lambda m: float(m.group(1)) * {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[m.group(2)] if m else 0
                return {"total": total, "used": used,
                        "swap_total": unit(re.search(r"total = ([\d.]+)([KMG])", sw)),
                        "swap_used": unit(re.search(r"used = ([\d.]+)([KMG])", sw))}
            except Exception:
                return None
        if os.name == "nt":
            try:
                import ctypes

                class MS(ctypes.Structure):
                    _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong),
                                ("avail", ctypes.c_ulonglong), ("pt", ctypes.c_ulonglong), ("pa", ctypes.c_ulonglong),
                                ("vt", ctypes.c_ulonglong), ("va", ctypes.c_ulonglong), ("e", ctypes.c_ulonglong)]
                m = MS()
                m.l = ctypes.sizeof(MS)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
                return {"total": m.total, "used": m.total - m.avail, "swap_total": 0, "swap_used": 0}
            except Exception:
                return None
        return None

    # ----- Network (ไบต์รวมทุกการ์ดยกเว้น loopback) -----
    def _net(self):
        if psutil:
            rx = tx = 0
            for name, c in psutil.net_io_counters(pernic=True).items():
                if not name.lower().startswith(("lo", "loopback")):
                    rx += c.bytes_recv
                    tx += c.bytes_sent
            return rx, tx
        if sys.platform.startswith("linux"):
            try:
                rx = tx = 0
                with open("/proc/net/dev") as f:
                    for line in f.readlines()[2:]:
                        name, data = line.split(":", 1)
                        if name.strip() == "lo":
                            continue
                        v = data.split()
                        rx += int(v[0])
                        tx += int(v[8])
                return rx, tx
            except Exception:
                return None
        if sys.platform == "darwin":
            try:
                rx = tx = 0
                seen = set()
                for line in _run(["netstat", "-ibn"]).splitlines()[1:]:
                    v = line.split()
                    if len(v) >= 10 and v[2].startswith("<Link#") and not v[0].startswith("lo") and v[0] not in seen:
                        seen.add(v[0])
                        n = len(v)
                        rx += int(v[n - 5])
                        tx += int(v[n - 2])
                return rx, tx
            except Exception:
                return None
        return None

    # ----- Disk -----
    def _disks(self):
        paths = []
        if psutil:
            try:
                paths = [p.mountpoint for p in psutil.disk_partitions(all=False)
                         if "cdrom" not in p.opts and p.fstype and not p.mountpoint.startswith(("/snap", "/boot/efi"))]
            except Exception:
                paths = []
        elif sys.platform.startswith("linux"):
            try:
                ok = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "ntfs", "exfat", "apfs", "hfs"}
                with open("/proc/mounts") as f:
                    for line in f:
                        dev, mnt, fs = line.split()[:3]
                        if fs in ok and not mnt.startswith(("/snap", "/boot/efi")):
                            paths.append(mnt.replace("\\040", " "))
            except Exception:
                pass
        elif sys.platform == "darwin":
            paths = ["/", "/System/Volumes/Data"]
        elif os.name == "nt":
            paths = ["%s:\\" % c for c in "CDEFGHIJ" if os.path.exists("%s:\\" % c)]
        here = os.path.dirname(os.path.abspath(__file__))
        out, seen = [], set()
        for p in paths + [here]:
            try:
                st = os.stat(p)
                key = st.st_dev
                u = shutil.disk_usage(p)
            except Exception:
                continue
            if key in seen:
                for d in out:
                    if d["dev"] == key and p == here:
                        d["relay"] = True
                continue
            seen.add(key)
            if u.total < 1024 ** 3 and p != here:          # ข้าม mount เล็ก ๆ ของระบบ (snap, tmp ฯลฯ)
                continue
            out.append({"path": p, "dev": key, "total": u.total, "used": u.total - u.free, "relay": p == here})
        for d in out:
            d.pop("dev", None)
        return out[:8]

    def _info(self):
        boot = None
        try:
            if psutil:
                boot = psutil.boot_time()
            elif sys.platform.startswith("linux"):
                with open("/proc/uptime") as f:
                    boot = time.time() - float(f.read().split()[0])
            elif sys.platform == "darwin":
                m = re.search(r"sec = (\d+)", _run(["sysctl", "-n", "kern.boottime"]))
                boot = int(m.group(1)) if m else None
            elif os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.GetTickCount64.restype = ctypes.c_ulonglong
                boot = time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000.0
        except Exception:
            pass
        rss = None
        try:
            if psutil:
                rss = psutil.Process().memory_info().rss
            elif sys.platform.startswith("linux"):
                with open("/proc/self/status") as f:
                    rss = int(re.search(r"VmRSS:\s+(\d+)", f.read()).group(1)) * 1024
            else:
                import resource
                r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                rss = r if sys.platform == "darwin" else r * 1024
        except Exception:
            pass
        try:
            load = os.getloadavg()
        except Exception:
            load = None
        osname = platform.platform(terse=True)
        if sys.platform == "darwin":
            v = platform.mac_ver()[0]
            osname = "macOS %s (%s)" % (v, platform.machine()) if v else osname
        return {"host": socket.gethostname(), "os": osname, "python": platform.python_version(), "cores": self.ncpu,
                "boot": boot, "rss": rss, "threads": threading.active_count(), "load": load,
                "psutil": bool(psutil)}

    def run(self):
        if psutil:
            psutil.cpu_percent(None)
        prev_cpu, prev_net, prev_relay, t0 = self._cpu_times(), self._net(), self.relay.bytes_now(), time.time()
        disks, info, n = self._disks(), self._info(), 0
        while True:
            time.sleep(self.interval)
            try:
                now = time.time()
                dt = max(0.1, now - t0)
                cpu_t, net, rb = self._cpu_times(), self._net(), self.relay.bytes_now()
                cpu = self._cpu_percent(prev_cpu, cpu_t)
                rx = tx = None
                if net and prev_net:
                    rx, tx = max(0, net[0] - prev_net[0]) / dt, max(0, net[1] - prev_net[1]) / dt
                relay_rate = max(0, rb - prev_relay) / dt
                mem = self._mem()
                n += 1
                if n % 15 == 0:                       # ทุก ~30 วินาที
                    disks, info = self._disks(), self._info()
                with self.lock:
                    self.cur = {"cpu": cpu, "mem": mem, "rx": rx, "tx": tx, "net_total": net, "relay_rate": relay_rate,
                                "disks": disks, "info": info}
                    self.hist.append({"t": now, "cpu": cpu,
                                      "mem": (100.0 * mem["used"] / mem["total"]) if mem and mem["total"] else None,
                                      "rx": rx, "tx": tx, "relay": relay_rate})
                prev_cpu, prev_net, prev_relay, t0 = cpu_t, net, rb, now
            except Exception as e:
                log("SysMon: %s" % e)

    def snapshot(self):
        with self.lock:
            d = dict(self.cur)
            d["hist"] = list(self.hist)
        d["info"] = dict(d.get("info") or self._info(), threads=threading.active_count())
        d["interval"] = self.interval
        return d


# ============================================================================
# ตั้งค่า Server จากหน้าเว็บ — เขียนลงไฟล์ .env แล้วโหลดค่าใหม่ (บางค่าต้องรีสตาร์ต)
# ============================================================================
# key, ชนิด, มีผลทันที (True) / ต้องรีสตาร์ต (False), ค่าเริ่มต้น, ตัวเลือก CLI
SETTINGS = [
    ("RELAY_PORT", "int", False, "5910", "--port"),
    ("RELAY_KEY", "secret", True, "", "--key"),
    ("RELAY_MAX_SESSIONS", "int", True, "50", "--max-sessions"),
    ("RELAY_STORE", "str", False, "relay_ids.json", "--store"),
    ("RELAY_UPDATES_DIR", "str", True, "", "--updates"),
    ("RELAY_WEB_PORT", "int", False, "5911", "--web-port"),
    ("RELAY_WEB_BIND", "str", False, "127.0.0.1", "--web-bind"),
    ("RELAY_ADMIN_KEY", "secret", True, "", "--admin-key"),
]
SETTING_KEYS = {s[0] for s in SETTINGS}


def parse_env_file(path):
    out = {}
    if not path or not os.path.isfile(path):
        return out
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


def write_env_file(path, updates):
    """แก้ค่าในไฟล์ .env โดยรักษาคอมเมนต์และลำดับเดิม — key ที่ยังไม่มีจะต่อท้ายไฟล์"""
    lines = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    done = set()

    def fmt(v):
        v = str(v)
        return '"%s"' % v if (v != v.strip() or " #" in v or v.startswith(("'", '"', "#"))) else v
    for i, line in enumerate(lines):
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k = s.split("=", 1)[0].strip()
        if k.startswith("export "):
            k = k[7:].strip()
        if k in updates and k not in done:
            lines[i] = "%s=%s" % (k, fmt(updates[k]))
            done.add(k)
    extra = [k for k in updates if k not in done]
    if extra:
        lines += ["", "# เพิ่มจากหน้าตั้งค่า Server (%s)" % time.strftime("%Y-%m-%d %H:%M")]
        lines += ["%s=%s" % (k, fmt(updates[k])) for k in extra]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


class Config:
    """ค่าที่ Relay ใช้อยู่ + ที่มาของแต่ละค่า (command line / ไฟล์ .env / ค่าเริ่มต้น)"""

    def __init__(self, env_path, args, argv):
        self.env_path = env_path
        self.cli = {k for k, _t, _l, _d, flag in SETTINGS if any(a == flag or a.startswith(flag + "=") for a in argv)}
        fv = self._file()
        for k in SETTING_KEYS:                       # เช่น systemd EnvironmentFile= ที่ชี้ไฟล์เดียวกัน → ถือว่ามาจากไฟล์
            if k in os.environ and fv.get(k) == os.environ[k]:
                ENV_FROM_FILE.add(k)
        self.base_env = {k: os.environ[k] for k in SETTING_KEYS if k in os.environ and k not in ENV_FROM_FILE}
        self.running = {
            "RELAY_PORT": str(args.port), "RELAY_KEY": args.key, "RELAY_MAX_SESSIONS": str(args.max_sessions),
            "RELAY_STORE": args.store, "RELAY_UPDATES_DIR": args.updates, "RELAY_WEB_PORT": str(args.web_port),
            "RELAY_WEB_BIND": args.web_bind, "RELAY_ADMIN_KEY": args.admin_key}
        self.started = dict(self.running)
        self.generated_admin = ""

    def _file(self):
        return parse_env_file(self.env_path)

    def source(self, k):
        if k in self.cli:
            return "cli"
        if k in self.base_env:
            return "environment"
        return "file" if k in self._file() else "default"

    def wanted(self, k, file_vals):
        """ค่าที่ควรใช้ตามไฟล์ .env ปัจจุบัน (command line / environment มีผลเหนือกว่าเสมอ)"""
        if k in self.cli:
            return self.started[k]
        if k in self.base_env:
            return self.base_env[k]
        default = next(s[3] for s in SETTINGS if s[0] == k)
        return file_vals.get(k, default)


def validate_settings(vals):
    errs = {}
    for k, typ, _live, _d, _f in SETTINGS:
        if k not in vals:
            continue
        v = str(vals[k])
        if "\n" in v or "\r" in v:
            errs[k] = "bad"
            continue
        if typ == "int":
            try:
                n = int(v)
            except ValueError:
                errs[k] = "int"
                continue
            if k in ("RELAY_PORT",) and not 1 <= n <= 65535:
                errs[k] = "port"
            if k == "RELAY_WEB_PORT" and not 0 <= n <= 65535:
                errs[k] = "port"
            if k == "RELAY_MAX_SESSIONS" and not 1 <= n <= 10000:
                errs[k] = "range"
        if k == "RELAY_WEB_BIND":
            try:
                if v not in ("localhost",):
                    socket.inet_pton(socket.AF_INET6 if ":" in v else socket.AF_INET, v)
            except OSError:
                errs[k] = "ip"
    return errs


def make_handler(relay):
    web_revoked, web_fails, web_lock = set(), {}, threading.Lock()

    def sign(body):
        return hmac.new(("nr-web:" + relay.admin_key()).encode(), body.encode(), hashlib.sha256).hexdigest()[:40]

    def make_token(age):
        # โทเค็นแบบลงลายเซ็นด้วยรหัส Admin — ใช้ต่อได้หลังรีสตาร์ต Relay, หมดอายุทันทีเมื่อเปลี่ยนรหัส Admin
        body = "%d.%s" % (time.time() + age, secrets.token_urlsafe(9))
        return body + "." + sign(body)

    def token_ok(tok):
        try:
            exp, nonce, sig = tok.split(".")
            return (float(exp) > time.time() and tok not in web_revoked
                    and hmac.compare_digest(sig, sign(exp + "." + nonce)))
        except Exception:
            return False

    class Handler(BaseHTTPRequestHandler):
        server_version = "NetRemoteRelay/" + VERSION

        def log_message(self, *a):
            pass

        def _ip(self):
            return self.client_address[0]

        def _cookie_token(self):
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "nr_session":
                    return v
            return ""

        def _authed(self):
            if not relay.admin_key():
                return True
            tok = self._cookie_token()
            if tok and token_ok(tok):
                return True
            h = self.headers.get("Authorization", "")      # ยังรองรับ Basic auth สำหรับสคริปต์ / curl
            if h.startswith("Basic "):
                try:
                    _user, _, pw = base64.b64decode(h[6:]).decode("utf-8").partition(":")
                    return hmac.compare_digest(pw, relay.admin_key())
                except Exception:
                    pass
            return False

        def _login(self):
            ip = self._ip()
            now = time.time()
            with web_lock:
                fails, until = web_fails.get(ip, (0, 0))
            try:
                n = min(int(self.headers.get("Content-Length", 0)), 4096)
                d = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                d = {}
            en = d.get("lang") == "en"
            if until > now:
                return self._json(429, {"ok": False, "err": (
                    "Too many wrong attempts — try again in %d seconds" if en else
                    "ใส่รหัสผิดหลายครั้ง — ลองใหม่ในอีก %d วินาที") % (until - now + 1)})
            pw = str(d.get("password", ""))
            admin_key = relay.admin_key()
            if admin_key and not hmac.compare_digest(pw.encode(), admin_key.encode()):
                fails += 1
                with web_lock:
                    web_fails[ip] = (0, now + 60) if fails >= 5 else (fails, 0)
                relay.event("warn", "เข้าสู่ระบบหน้ามอนิเตอร์ไม่สำเร็จจาก %s" % ip)
                time.sleep(0.4)
                left = 5 - fails
                if fails >= 5:
                    msg = "5 wrong attempts — locked for 60 seconds" if en else "ใส่รหัสผิด 5 ครั้ง — ล็อก 60 วินาที"
                elif en:
                    msg = "Incorrect password" + (" (%d attempts left)" % left if 0 < left < 5 else "")
                else:
                    msg = "รหัสผ่านไม่ถูกต้อง" + (" (เหลืออีก %d ครั้ง)" % left if 0 < left < 5 else "")
                return self._json(401, {"ok": False, "err": msg})
            age = 30 * 86400 if d.get("remember") else 12 * 3600
            tok = make_token(age)
            with web_lock:
                web_fails.pop(ip, None)
            relay.event("info", "ผู้ดูแลเข้าสู่ระบบหน้ามอนิเตอร์จาก %s" % ip)
            cookie = "nr_session=%s; Path=/; HttpOnly; SameSite=Strict" % tok
            if d.get("remember"):
                cookie += "; Max-Age=%d" % age
            self._json(200, {"ok": True}, [("Set-Cookie", cookie)])

        def _save_settings(self, d):
            vals = {k: str(v).strip() for k, v in (d.get("values") or {}).items() if k in SETTING_KEYS}
            c = relay.conf
            vals = {k: v for k, v in vals.items() if c.source(k) not in ("cli", "environment")}
            errs = validate_settings(vals)
            if errs:
                return self._json(400, {"ok": False, "errors": errs})
            fv = parse_env_file(c.env_path)
            merged = dict((k, c.wanted(k, fv)) for k in SETTING_KEYS)
            merged.update(vals)
            local = merged["RELAY_WEB_BIND"] in ("127.0.0.1", "localhost", "::1")
            if not local and not merged["RELAY_ADMIN_KEY"] and not merged["RELAY_KEY"]:
                return self._json(400, {"ok": False, "errors": {"RELAY_ADMIN_KEY": "need_admin"}})
            if not c.env_path:
                c.env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
            try:
                write_env_file(c.env_path, vals)
            except OSError as e:
                return self._json(500, {"ok": False, "err": str(e)})
            changed, pending = relay.apply_settings("save")
            self._json(200, {"ok": True, "changed": changed, "pending": pending})

        def _redirect(self, where, headers=()):
            self.send_response(302)
            self.send_header("Location", where)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _json(self, code, obj, headers=()):
            self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8", headers)

        def _send(self, code, body, ctype, headers=()):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/login":
                if relay.admin_key() and self._authed():
                    return self._redirect("./")
                return self._send(200, LOGIN_PAGE.replace("__VER__", VERSION), "text/html; charset=utf-8")
            if path == "/logout":
                with web_lock:
                    web_revoked.add(self._cookie_token())
                return self._redirect("login", [("Set-Cookie", "nr_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")])
            if not self._authed():
                if path.startswith("/api/"):
                    return self._json(401, {"ok": False, "err": "login"})
                return self._redirect("login")
            if path in ("/", "/index.html"):
                self._send(200, DASHBOARD.replace("__LOGOUT__", "" if relay.admin_key() else "hidden"), "text/html; charset=utf-8")
            elif path == "/api/state":
                self._send(200, json.dumps(relay.snapshot(), ensure_ascii=False), "application/json; charset=utf-8")
            elif path == "/api/system":
                self._json(200, relay.sysmon.snapshot() if getattr(relay, "sysmon", None) else {})
            elif path == "/api/settings":
                self._json(200, relay.settings_view())
            elif path == "/api/updates":
                self._json(200, relay.updates_view())
            else:
                self._send(404, "not found", "text/plain")

        def do_POST(self):
            if self.path.split("?")[0] == "/login":
                return self._login()
            if not self._authed():
                return self._json(401, {"ok": False, "err": "login"})
            path = self.path.split("?")[0]
            if path == "/api/updates/upload":
                from urllib.parse import parse_qs, urlparse
                name = (parse_qs(urlparse(self.path).query).get("name") or [""])[0]
                try:
                    saved = relay.save_update_file(name, self.rfile, int(self.headers.get("Content-Length", 0)))
                except ValueError as e:
                    return self._json(400, {"ok": False, "err": str(e)})
                except Exception as e:
                    return self._json(500, {"ok": False, "err": str(e)})
                return self._json(200, {"ok": True, "name": saved})
            try:
                n = min(int(self.headers.get("Content-Length", 0)), 65536)
                d = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                d = {}
            if path.startswith("/api/updates/"):
                try:
                    if path == "/api/updates/publish":
                        relay.publish_update(d)
                    elif path == "/api/updates/unpublish":
                        relay.unpublish_update()
                    elif path == "/api/updates/delete":
                        relay.delete_update_file(d.get("name"))
                    else:
                        return self._send(404, "not found", "text/plain")
                except ValueError as e:
                    return self._json(400, {"ok": False, "err": str(e)})
                except OSError as e:
                    return self._json(500, {"ok": False, "err": str(e)})
                return self._json(200, {"ok": True})
            if path == "/api/settings":
                return self._save_settings(d)
            if path == "/api/reload":
                changed, pending = relay.apply_settings("reload")
                return self._json(200, {"ok": True, "changed": changed, "pending": pending})
            if path == "/api/restart":
                self._json(200, {"ok": True, "web_port": relay.settings_view()["items"][5]["value"]})
                relay.event("warn", "ผู้ดูแลสั่งรีสตาร์ต Relay")
                threading.Thread(target=restart_self, daemon=True).start()
                return
            if path != "/api/kick":
                self._send(404, "not found", "text/plain")
                return
            ok = relay.kick_session(str(d["sid"])) if "sid" in d else (
                relay.kick_host(str(d["host"])) if "host" in d else False)
            self._send(200, json.dumps({"ok": ok}), "application/json")
    return Handler


def restart_self():
    """รีสตาร์ต Relay (กระบวนการเดิม) เพื่อใช้ค่าที่ต้องรีสตาร์ต เช่นพอร์ต"""
    time.sleep(0.8)
    log("กำลังรีสตาร์ต…")
    try:
        sys.stdout.flush()
    except Exception:
        pass
    for k in ENV_FROM_FILE:                         # ให้รอบใหม่อ่านค่าจากไฟล์ .env ล่าสุด
        os.environ.pop(k, None)
    os.execv(sys.executable, [sys.executable] + sys.argv)


def start_web(relay, bind, port):
    admin_key = relay.admin_key()
    class QuietServer(ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)):
                super().handle_error(request, client_address)
    httpd = QuietServer((bind, port), make_handler(relay))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    shown = "localhost" if bind in ("127.0.0.1", "localhost") else (bind if bind not in ("0.0.0.0", "") else "<IP ของเครื่องนี้>")
    log("หน้ามอนิเตอร์: http://%s:%d %s" % (shown, port, "(ต้องใส่รหัส Admin)" if admin_key else ""))


def load_env(path):
    """อ่านไฟล์ .env (KEY=VALUE) แล้วตั้งเป็น environment — ค่าที่ตั้งไว้ใน environment อยู่แล้วมีผลเหนือกว่า"""
    if not path or not os.path.isfile(path):
        return None
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
            if k not in os.environ:
                os.environ[k] = v
                ENV_FROM_FILE.add(k)
    return path


ENV_FROM_FILE = set()


def main():
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--env", default=os.environ.get("RELAY_ENV",
                                                     os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")))
    want_env = pre.parse_known_args()[0].env
    env_path = load_env(want_env) or want_env
    p = argparse.ArgumentParser(description="NetRemote Relay Server")
    p.add_argument("--env", help="ไฟล์ตั้งค่า (ค่าเริ่มต้น: .env ในโฟลเดอร์เดียวกับโปรแกรมนี้)")
    p.add_argument("--port", type=int, default=int(os.environ.get("RELAY_PORT", 5910)))
    p.add_argument("--key", default=os.environ.get("RELAY_KEY", ""),
                   help="Relay Key — ผู้ใช้ต้องใส่ให้ตรงจึงจะใช้ Relay ได้ (แนะนำให้ตั้ง)")
    p.add_argument("--store", default=os.environ.get("RELAY_STORE", "relay_ids.json"),
                   help="ไฟล์เก็บ ID ที่ลงทะเบียนแล้ว")
    p.add_argument("--max-sessions", type=int, default=int(os.environ.get("RELAY_MAX_SESSIONS", 50)))
    p.add_argument("--updates", default=os.environ.get("RELAY_UPDATES_DIR", ""),
                   help="โฟลเดอร์ไฟล์อัปเดตโปรแกรม (latest.json + .dmg/.exe) ค่าเริ่มต้น: updates/ ข้างโปรแกรมนี้")
    p.add_argument("--web-port", type=int, default=int(os.environ.get("RELAY_WEB_PORT", 5911)),
                   help="พอร์ตหน้ามอนิเตอร์ (0 = ปิด)")
    p.add_argument("--web-bind", default=os.environ.get("RELAY_WEB_BIND", "127.0.0.1"),
                   help="127.0.0.1 = ดูได้จากเครื่องนี้เท่านั้น (ค่าเริ่มต้น), 0.0.0.0 = เปิดให้เครื่องอื่นดูได้")
    p.add_argument("--admin-key", default=os.environ.get("RELAY_ADMIN_KEY", ""),
                   help="รหัสเข้าหน้ามอนิเตอร์ (ถ้าไม่ตั้ง ใช้ Relay Key)")
    a = p.parse_args()
    if os.path.isfile(env_path):
        log("อ่านการตั้งค่าจาก %s" % env_path)
    if not a.key:
        log("⚠ ไม่ได้ตั้ง --key — แนะนำให้ตั้งเพื่อกันคนอื่นใช้ Relay ของคุณ")
    upd = a.updates or os.path.join(os.path.dirname(os.path.abspath(__file__)), "updates")
    relay = Relay(a.port, a.key, a.store, a.max_sessions, upd)
    relay.conf = Config(env_path, a, sys.argv[1:])
    relay.default_updates = os.path.join(os.path.dirname(os.path.abspath(__file__)), "updates")
    relay.sysmon = SysMon(relay)
    relay.sysmon.start()
    if os.path.isfile(os.path.join(upd, "latest.json")):
        log("แจกอัปเดตโปรแกรมจาก %s (เวอร์ชัน %s)" % (upd, relay.update_info().get("version")))
    if a.web_port:
        admin = a.admin_key or a.key
        local_only = a.web_bind in ("127.0.0.1", "localhost", "::1")
        if not local_only and not admin:
            admin = secrets.token_urlsafe(9)
            relay.conf.generated_admin = admin
            log("⚠ เปิดหน้ามอนิเตอร์ให้เครื่องอื่นดูได้ จึงสร้างรหัส Admin ให้: %s" % admin)
        try:
            start_web(relay, a.web_bind, a.web_port)
        except OSError as e:
            log("⚠ เปิดหน้ามอนิเตอร์ไม่ได้ (พอร์ต %d): %s" % (a.web_port, e))
    try:
        relay.serve()
    except KeyboardInterrupt:
        log("หยุดแล้ว")


if __name__ == "__main__":
    main()
