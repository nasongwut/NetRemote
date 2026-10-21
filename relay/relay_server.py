#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetRemote Relay Server — ตัวกลางสำหรับรีโมทผ่านอินเทอร์เน็ต
=========================================================
ติดตั้งบนเครื่องที่มี IP สาธารณะ (VPS / Cloud / Server ที่เปิดพอร์ตได้)
ใช้แค่ Python 3.8+ ไม่ต้องติดตั้งไลบรารีเพิ่ม

    python3 relay_server.py --port 5910 --key รหัสสำหรับใช้Relay

การทำงาน
  - เครื่องที่ถูกควบคุม (host) เชื่อมต่อเข้ามาลงทะเบียน ID 9 หลัก และค้างการเชื่อมต่อไว้
  - เครื่องที่ควบคุม (client) ขอเชื่อมต่อไปยัง ID นั้น
  - Relay สั่งให้ host เปิดการเชื่อมต่อข้อมูลใหม่ แล้วต่อท่อ (pipe) ระหว่าง client ↔ host
  - ข้อมูลภายในท่อเข้ารหัส TLS จากต้นทางถึงปลายทาง — Relay อ่านหน้าจอ/ไฟล์/รหัสผ่านไม่ได้
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
from collections import defaultdict, deque

VERSION = "1.0"
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
        self.sessions = 0
        self.lock = threading.Lock()
        self.rate = defaultdict(deque)
        self.bad = defaultdict(deque)
        self.secrets = {}
        try:
            with open(store, encoding="utf-8") as f:
                self.secrets = json.load(f)
        except Exception:
            pass

    # ----- helpers -----
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
        log("NetRemote Relay %s เริ่มทำงานที่พอร์ต %d %s" % (VERSION, self.port,
                                                         "(ใช้ Relay Key)" if self.key else "(ไม่มี Relay Key — ใครก็ใช้ได้)"))
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
                log("key ผิดจาก", ip)
                return
            if role == "ping":
                line_send(conn, {"ok": True, "v": VERSION, "hosts": len(self.hosts), "sessions": self.sessions})
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
                log("ID ชน", hid, "จาก", ip)
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
        log("host ออนไลน์ ID %s (%s, %s)" % (hid, hc.name, ip))
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
                    log("host ออฟไลน์ ID", hid)

    def _client(self, conn, ip, msg):
        hid = re.sub(r"\D", "", str(msg.get("id", "")))
        with self.lock:
            hc = self.hosts.get(hid)
            busy = self.sessions >= self.max_sessions
        if busy:
            line_send(conn, {"ok": False, "err": "Relay มีผู้ใช้งานเต็มแล้ว ลองใหม่ภายหลัง"})
            return False
        if not hc:
            line_send(conn, {"ok": False, "err": "ไม่พบเครื่อง ID %s หรือเครื่องนั้นไม่ได้เปิดรับการเชื่อมต่อ" % hid})
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
        log("เริ่มเซสชัน %s → ID %s" % (ip, hid))
        threading.Thread(target=self._pipe, args=(conn, pend["sock"], ip, hid), daemon=True).start()
        return True

    def _data(self, conn, msg):
        with self.lock:
            pend = self.pending.get(str(msg.get("token", "")))
            if not pend or pend["sock"] is not None:
                return False
            pend["sock"] = conn
        pend["ev"].set()
        return True

    def _pipe(self, a, b, ip, hid):
        with self.lock:
            self.sessions += 1
        a.settimeout(None)
        b.settimeout(None)
        total = [0, 0]
        t0 = time.time()

        def copy(src, dst, i):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
                    total[i] += len(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t = threading.Thread(target=copy, args=(b, a, 1), daemon=True)
        t.start()
        copy(a, b, 0)
        t.join()
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass
        with self.lock:
            self.sessions -= 1
        mb = (total[0] + total[1]) / 1024 / 1024
        log("จบเซสชัน %s → ID %s  (%.0f วินาที, %.1f MB)" % (ip, hid, time.time() - t0, mb))


def main():
    p = argparse.ArgumentParser(description="NetRemote Relay Server")
    p.add_argument("--port", type=int, default=int(os.environ.get("RELAY_PORT", 5910)))
    p.add_argument("--key", default=os.environ.get("RELAY_KEY", ""),
                   help="Relay Key — ผู้ใช้ต้องใส่ให้ตรงจึงจะใช้ Relay ได้ (แนะนำให้ตั้ง)")
    p.add_argument("--store", default=os.environ.get("RELAY_STORE", "relay_ids.json"),
                   help="ไฟล์เก็บ ID ที่ลงทะเบียนแล้ว")
    p.add_argument("--max-sessions", type=int, default=50)
    a = p.parse_args()
    if not a.key:
        log("⚠ ไม่ได้ตั้ง --key — แนะนำให้ตั้งเพื่อกันคนอื่นใช้ Relay ของคุณ")
    try:
        Relay(a.port, a.key, a.store, a.max_sessions).serve()
    except KeyboardInterrupt:
        log("หยุดแล้ว")


if __name__ == "__main__":
    main()
