"""ตั้งเลขเวอร์ชันอัตโนมัติตอน build บน GitHub
VERSION ในไฟล์ = เลขหลัก (เช่น 1.7) → เวอร์ชันที่ build = 1.7.<จำนวน commit ทั้งหมด> เช่น 1.7.142
push ใหม่ทุกครั้ง เลขท้ายจะเพิ่มเอง  ·  เปลี่ยนรุ่นใหญ่ → แก้ VERSION ในไฟล์เป็น 1.8 เอง"""
import os
import re
import subprocess

SRC = "remote_desktop.py"
s = open(SRC, encoding="utf-8").read()
m = re.search(r'^VERSION = "([^"]+)"', s, re.M)
base = ".".join(m.group(1).split(".")[:2])
n = subprocess.check_output(["git", "rev-list", "--count", "HEAD"], text=True).strip()
ver = "%s.%s" % (base, n)
s = s[:m.start()] + 'VERSION = "%s"' % ver + s[m.end():]
open(SRC, "w", encoding="utf-8", newline="").write(s)
with open(os.environ.get("GITHUB_ENV", os.devnull), "a", encoding="utf-8") as f:
    f.write("APP_VERSION=%s\n" % ver)
print("version:", ver)
