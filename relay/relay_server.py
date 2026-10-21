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
import re
import secrets
import socket
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.1"
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


class HostConn:
    def __init__(self, sock, ip, name):
        self.sock, self.ip, self.name = sock, ip, name
        self.lock = threading.Lock()
        self.since = time.time()

    def send(self, obj):
        with self.lock:
            line_send(self.sock, obj)


class Relay:
    def __init__(self, port, key, store, max_sessions):
        self.port, self.key, self.store = port, key or "", store
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
    def event(self, kind, text):
        log(text)
        self.events.appendleft({"t": time.time(), "kind": kind, "text": text})

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
            hc = HostConn(conn, ip, str(msg.get("name", ""))[:60])
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
            line_send(conn, {"ok": False, "err": "ไม่พบเครื่อง ID %s หรือเครื่องนั้นไม่ได้เปิดรับการเชื่อมต่อ" % hid})
            self.event("warn", "%s ขอเชื่อมต่อ ID %s แต่เครื่องไม่ออนไลน์" % (ip, hid))
            return False
        token = secrets.token_hex(16)
        pend = {"ev": threading.Event(), "sock": None}
        with self.lock:
            self.pending[token] = pend
        try:
            hc.send({"cmd": "connect", "token": token, "from": ip})
        except Exception:
            with self.lock:
                self.pending.pop(token, None)
            line_send(conn, {"ok": False, "err": "เครื่องปลายทางไม่ตอบสนอง"})
            return False
        ok = pend["ev"].wait(15)
        with self.lock:
            self.pending.pop(token, None)
        if not ok or pend["sock"] is None:
            line_send(conn, {"ok": False, "err": "เครื่องปลายทางไม่ตอบสนอง"})
            return False
        line_send(conn, {"ok": True})
        threading.Thread(target=self._pipe, args=(conn, pend["sock"], ip, hid, hc), daemon=True).start()
        return True

    def _data(self, conn, msg):
        with self.lock:
            pend = self.pending.get(str(msg.get("token", "")))
            if not pend or pend["sock"] is not None:
                return False
            pend["sock"] = conn
        pend["ev"].set()
        return True

    def _pipe(self, a, b, ip, hid, hc):
        sid = secrets.token_hex(6)
        sess = {"sid": sid, "client": ip, "hid": hid, "hname": hc.name, "hip": hc.ip,
                "start": time.time(), "up": 0, "down": 0, "socks": (a, b)}
        with self.lock:
            self.sessions[sid] = sess
            self.stats["sessions_total"] += 1
        self.event("connect", "%s เริ่มควบคุมเครื่อง %s (ID %s)" % (ip, hc.name or "-", hid))
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
                          "rate_up": ru, "rate_down": rd})
        out_s.sort(key=lambda x: -x["dur"])
        out_h = [{"id": hid, "name": hc.name, "ip": hc.ip, "online": now - hc.since, "sessions": busy[hid]}
                 for hid, hc in sorted(hosts, key=lambda kv: kv[1].since)]
        live = sum(s["up"] + s["down"] for s in sessions)
        return {"version": VERSION, "uptime": now - self.started, "port": self.port, "hosts": out_h,
                "sessions": out_s, "events": list(self.events)[:100],
                "stats": dict(self.stats, bytes_total=self.stats["bytes_total"] + live,
                              rate=sum(s["rate_up"] + s["rate_down"] for s in out_s),
                              registered=len(self.secrets))}

    def kick_session(self, sid):
        with self.lock:
            s = self.sessions.get(sid)
        if not s:
            return False
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
<title>NetRemote Relay Monitor</title>
<style>
:root{--bg:#F3F4F8;--card:#fff;--border:#E3E6EE;--text:#1D2130;--muted:#6B7280;--subtle:#EEF0F6;
--accent:#6D4AFF;--sel:#ECE7FF;--ok:#15803D;--okbg:#E6F6EC;--warn:#B45309;--warnbg:#FFF3E0;--danger:#DC2626;
--dangerbg:#FDECEC;--hdr:#5B3AE6}
@media (prefers-color-scheme:dark){:root{--bg:#121419;--card:#1B1E26;--border:#2B303B;--text:#E8EAF0;
--muted:#9AA3B2;--subtle:#252A34;--accent:#8B6CFF;--sel:#352C5E;--ok:#4ADE80;--okbg:#14301F;--warn:#FBBF24;
--warnbg:#3A2B10;--danger:#F87171;--dangerbg:#3A1818;--hdr:#2E2370}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans Thai","Sukhumvit Set",sans-serif}
header{background:var(--hdr);color:#fff;padding:16px 24px;display:flex;align-items:center;gap:14px}
.logo{width:38px;height:38px;border-radius:10px;background:#fff;display:grid;place-items:center}
.logo i{width:20px;height:13px;border-radius:2px;background:var(--hdr);display:block;position:relative}
.logo i:after{content:"";position:absolute;left:7px;top:15px;width:6px;height:4px;background:var(--hdr)}
header h1{font-size:19px;margin:0}header small{opacity:.8}header .sp{flex:1}
.live{font-size:12px;background:rgba(255,255,255,.15);padding:5px 12px;border-radius:99px}
.live b{display:inline-block;width:8px;height:8px;border-radius:50%;background:#4ADE80;margin-right:6px}
main{padding:20px 24px;max-width:1280px;margin:0 auto}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px}
.stat{padding:14px 18px}.stat .k{color:var(--muted);font-size:12px;font-weight:600}
.stat .v{font-size:26px;font-weight:700;margin-top:2px}.stat .s{color:var(--muted);font-size:12px}
.grid{display:grid;grid-template-columns:1.2fr 1fr;gap:16px}
@media(max-width:980px){.grid{grid-template-columns:1fr}}
.card h2{font-size:16px;margin:0;padding:16px 18px 6px;display:flex;align-items:center;gap:8px}
.card h2 .n{background:var(--sel);color:var(--accent);font-size:12px;padding:1px 9px;border-radius:99px}
.hint{color:var(--muted);font-size:12px;padding:0 18px 10px}
table{width:100%;border-collapse:collapse}
th{font-size:11px;color:var(--muted);text-align:left;background:var(--subtle);padding:8px 12px;font-weight:600;white-space:nowrap}
td{padding:10px 12px;border-top:1px solid var(--border);vertical-align:middle}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:600}
.pill{font-size:11px;font-weight:700;padding:2px 9px;border-radius:99px;white-space:nowrap}
.p-ok{background:var(--okbg);color:var(--ok)}.p-busy{background:var(--dangerbg);color:var(--danger)}
.arrow{color:var(--accent);font-weight:700;padding:0 6px}
.muted{color:var(--muted)}.small{font-size:12px}
button{border:0;border-radius:8px;padding:6px 12px;font:inherit;font-size:12px;font-weight:600;cursor:pointer;
background:var(--dangerbg);color:var(--danger)}button:hover{background:var(--danger);color:#fff}
.empty{padding:26px;text-align:center;color:var(--muted)}
.ev{display:flex;gap:10px;padding:8px 18px;border-top:1px solid var(--border);font-size:13px}
.ev time{color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
.dot{width:8px;height:8px;border-radius:50%;margin-top:7px;flex:none;background:var(--muted)}
.d-online,.d-connect{background:var(--ok)}.d-offline,.d-disconnect{background:var(--muted)}
.d-warn{background:var(--warn)}.events{max-height:430px;overflow:auto;padding-bottom:6px}
.err{background:var(--dangerbg);color:var(--danger);padding:10px 14px;border-radius:10px;margin-bottom:14px;display:none}
</style></head><body>
<header><div class="logo"><i></i></div><div><h1>NetRemote Relay Monitor</h1>
<small id="sub">กำลังโหลด…</small></div><div class="sp"></div><span class="live"><b></b>อัปเดตอัตโนมัติ</span></header>
<main>
<div class="err" id="err"></div>
<div class="stats">
 <div class="card stat"><div class="k">เครื่องออนไลน์</div><div class="v" id="s-hosts">–</div><div class="s">พร้อมให้เชื่อมต่อ</div></div>
 <div class="card stat"><div class="k">กำลังเชื่อมต่ออยู่</div><div class="v" id="s-sess">–</div><div class="s">เซสชันรีโมท</div></div>
 <div class="card stat"><div class="k">ความเร็วรวมตอนนี้</div><div class="v" id="s-rate">–</div><div class="s">ผ่าน Relay</div></div>
 <div class="card stat"><div class="k">ข้อมูลรวม</div><div class="v" id="s-bytes">–</div><div class="s" id="s-total">–</div></div>
 <div class="card stat"><div class="k">Relay ทำงานมาแล้ว</div><div class="v" id="s-up">–</div><div class="s" id="s-fail">–</div></div>
</div>
<div class="grid">
 <div>
  <div class="card" style="margin-bottom:16px"><h2>กำลังเชื่อมต่ออยู่ <span class="n" id="n-sess">0</span></h2>
   <div class="hint">ใครกำลังรีโมทเข้าเครื่องไหน — ข้อมูลเข้ารหัสต้นทางถึงปลายทาง Relay มองไม่เห็นเนื้อหา</div>
   <table><thead><tr><th>ผู้ควบคุม (IP)</th><th></th><th>เครื่องปลายทาง</th><th style="text-align:right">เวลา</th>
   <th style="text-align:right">ข้อมูล</th><th style="text-align:right">ความเร็ว</th><th></th></tr></thead>
   <tbody id="t-sess"></tbody></table></div>
  <div class="card"><h2>เครื่องที่ออนไลน์ <span class="n" id="n-hosts">0</span></h2>
   <div class="hint">เครื่องที่เปิด "รับการเชื่อมต่อผ่านอินเทอร์เน็ต" และเชื่อมกับ Relay อยู่</div>
   <table><thead><tr><th>ID</th><th>ชื่อเครื่อง</th><th>IP</th><th style="text-align:right">ออนไลน์มาแล้ว</th>
   <th>สถานะ</th><th></th></tr></thead><tbody id="t-hosts"></tbody></table></div>
 </div>
 <div class="card"><h2>เหตุการณ์ล่าสุด</h2><div class="events" id="events"></div></div>
</div>
</main>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fb=n=>{n=+n||0;const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?n.toFixed(1):Math.round(n))+" "+u[i]};
const fd=s=>{s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),x=s%60;
 return d?`${d} วัน ${h} ชม.`:h?`${h}:${String(m).padStart(2,"0")}:${String(x).padStart(2,"0")}`:`${m}:${String(x).padStart(2,"0")}`};
const fid=i=>String(i).replace(/(\d{3})(\d{3})(\d{3})/,"$1 $2 $3");
const tm=t=>new Date(t*1000).toLocaleTimeString("th-TH",{hour12:false});
async function kick(kind,val){
 const msg=kind==="sid"?"ตัดการเชื่อมต่อเซสชันนี้?":"ตัดเครื่องนี้ออกจาก Relay? (เครื่องจะเชื่อมต่อกลับเองภายหลัง)";
 if(!confirm(msg))return;
 await fetch("api/kick",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({[kind]:val})});
 load();
}
async function load(){
 try{
  const r=await fetch("api/state",{cache:"no-store"});
  if(!r.ok)throw new Error("HTTP "+r.status);
  const d=await r.json(); $("err").style.display="none";
  $("sub").textContent=`Relay v${d.version} · พอร์ต ${d.port} · อัปเดต ${new Date().toLocaleTimeString("th-TH",{hour12:false})}`;
  $("s-hosts").textContent=d.hosts.length; $("s-sess").textContent=d.sessions.length;
  $("s-rate").textContent=fb(d.stats.rate)+"/s"; $("s-bytes").textContent=fb(d.stats.bytes_total);
  $("s-total").textContent=`ทั้งหมด ${d.stats.sessions_total} เซสชัน · ลงทะเบียน ${d.stats.registered} ID`;
  $("s-up").textContent=fd(d.uptime); $("s-fail").textContent=`Relay Key ผิด ${d.stats.auth_fail} ครั้ง`;
  $("n-sess").textContent=d.sessions.length; $("n-hosts").textContent=d.hosts.length;
  $("t-sess").innerHTML=d.sessions.length?d.sessions.map(s=>`<tr>
   <td class="mono">${esc(s.client)}</td><td class="arrow">→</td>
   <td><b>${esc(s.hname||"-")}</b><div class="small muted mono" style="white-space:nowrap">ID ${fid(s.hid)}</div></td>
   <td class="num">${fd(s.dur)}</td><td class="num">${fb(s.up+s.down)}</td>
   <td class="num">${fb(s.rate_up+s.rate_down)}/s<div class="small muted">↑${fb(s.rate_up)} ↓${fb(s.rate_down)}</div></td>
   <td class="num"><button onclick="kick('sid','${s.sid}')">ตัดการเชื่อมต่อ</button></td></tr>`).join("")
   :`<tr><td colspan="7" class="empty">ยังไม่มีใครเชื่อมต่อ</td></tr>`;
  $("t-hosts").innerHTML=d.hosts.length?d.hosts.map(h=>`<tr>
   <td class="mono">${fid(h.id)}</td><td><b>${esc(h.name||"-")}</b></td><td class="mono small">${esc(h.ip)}</td>
   <td class="num">${fd(h.online)}</td>
   <td>${h.sessions?`<span class="pill p-busy">● กำลังถูกควบคุม</span>`:`<span class="pill p-ok">● ว่าง</span>`}</td>
   <td class="num"><button onclick="kick('host','${h.id}')">ตัดออก</button></td></tr>`).join("")
   :`<tr><td colspan="6" class="empty">ยังไม่มีเครื่องออนไลน์</td></tr>`;
  $("events").innerHTML=d.events.length?d.events.map(e=>`<div class="ev"><span class="dot d-${e.kind}"></span>
   <time>${tm(e.t)}</time><span>${esc(e.text)}</span></div>`).join(""):`<div class="empty">ยังไม่มีเหตุการณ์</div>`;
 }catch(e){$("err").textContent="เชื่อมต่อ Relay ไม่ได้: "+e.message;$("err").style.display="block"}
}
load(); setInterval(load,2000);
</script></body></html>"""


def make_handler(relay, admin_key):
    class Handler(BaseHTTPRequestHandler):
        server_version = "NetRemoteRelay/" + VERSION

        def log_message(self, *a):
            pass

        def _auth(self):
            if not admin_key:
                return True
            h = self.headers.get("Authorization", "")
            if h.startswith("Basic "):
                try:
                    _user, _, pw = base64.b64decode(h[6:]).decode("utf-8").partition(":")
                    if hmac.compare_digest(pw, admin_key):
                        return True
                except Exception:
                    pass
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="NetRemote Relay Monitor", charset="UTF-8"')
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write("ต้องใส่รหัส Admin (ชื่อผู้ใช้อะไรก็ได้)".encode("utf-8"))
            return False

        def _send(self, code, body, ctype):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self._auth():
                return
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                self._send(200, DASHBOARD, "text/html; charset=utf-8")
            elif path == "/api/state":
                self._send(200, json.dumps(relay.snapshot(), ensure_ascii=False), "application/json; charset=utf-8")
            else:
                self._send(404, "not found", "text/plain")

        def do_POST(self):
            if not self._auth():
                return
            if self.path.split("?")[0] != "/api/kick":
                self._send(404, "not found", "text/plain")
                return
            try:
                n = min(int(self.headers.get("Content-Length", 0)), 4096)
                d = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                d = {}
            ok = relay.kick_session(str(d["sid"])) if "sid" in d else (
                relay.kick_host(str(d["host"])) if "host" in d else False)
            self._send(200, json.dumps({"ok": ok}), "application/json")
    return Handler


def start_web(relay, bind, port, admin_key):
    httpd = ThreadingHTTPServer((bind, port), make_handler(relay, admin_key))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    shown = "localhost" if bind in ("127.0.0.1", "localhost") else (bind if bind not in ("0.0.0.0", "") else "<IP ของเครื่องนี้>")
    log("หน้ามอนิเตอร์: http://%s:%d %s" % (shown, port, "(ต้องใส่รหัส Admin)" if admin_key else ""))


def main():
    p = argparse.ArgumentParser(description="NetRemote Relay Server")
    p.add_argument("--port", type=int, default=int(os.environ.get("RELAY_PORT", 5910)))
    p.add_argument("--key", default=os.environ.get("RELAY_KEY", ""),
                   help="Relay Key — ผู้ใช้ต้องใส่ให้ตรงจึงจะใช้ Relay ได้ (แนะนำให้ตั้ง)")
    p.add_argument("--store", default=os.environ.get("RELAY_STORE", "relay_ids.json"),
                   help="ไฟล์เก็บ ID ที่ลงทะเบียนแล้ว")
    p.add_argument("--max-sessions", type=int, default=50)
    p.add_argument("--web-port", type=int, default=int(os.environ.get("RELAY_WEB_PORT", 5911)),
                   help="พอร์ตหน้ามอนิเตอร์ (0 = ปิด)")
    p.add_argument("--web-bind", default=os.environ.get("RELAY_WEB_BIND", "127.0.0.1"),
                   help="127.0.0.1 = ดูได้จากเครื่องนี้เท่านั้น (ค่าเริ่มต้น), 0.0.0.0 = เปิดให้เครื่องอื่นดูได้")
    p.add_argument("--admin-key", default=os.environ.get("RELAY_ADMIN_KEY", ""),
                   help="รหัสเข้าหน้ามอนิเตอร์ (ถ้าไม่ตั้ง ใช้ Relay Key)")
    a = p.parse_args()
    if not a.key:
        log("⚠ ไม่ได้ตั้ง --key — แนะนำให้ตั้งเพื่อกันคนอื่นใช้ Relay ของคุณ")
    relay = Relay(a.port, a.key, a.store, a.max_sessions)
    if a.web_port:
        admin = a.admin_key or a.key
        local_only = a.web_bind in ("127.0.0.1", "localhost", "::1")
        if not local_only and not admin:
            admin = secrets.token_urlsafe(9)
            log("⚠ เปิดหน้ามอนิเตอร์ให้เครื่องอื่นดูได้ จึงสร้างรหัส Admin ให้: %s" % admin)
        try:
            start_web(relay, a.web_bind, a.web_port, "" if local_only and not a.admin_key else admin)
        except OSError as e:
            log("⚠ เปิดหน้ามอนิเตอร์ไม่ได้ (พอร์ต %d): %s" % (a.web_port, e))
    try:
        relay.serve()
    except KeyboardInterrupt:
        log("หยุดแล้ว")


if __name__ == "__main__":
    main()
