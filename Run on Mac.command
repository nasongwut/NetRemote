#!/bin/bash
# ดับเบิลคลิกเพื่อเปิด NetRemote (macOS) — ครั้งแรกจะติดตั้งไลบรารีให้อัตโนมัติ
cd "$(dirname "$0")"
PY="$(command -v python3)"
if [ -z "$PY" ]; then
  echo "ไม่พบ Python 3 — ติดตั้งได้จาก https://www.python.org/downloads/"
  read -p "กด Enter เพื่อปิด"; exit 1
fi
if [ ! -f .venv/.installed ] || [ requirements.txt -nt .venv/.installed ]; then
  echo "กำลังติดตั้งไลบรารี (ประมาณ 1-2 นาที ต้องต่ออินเทอร์เน็ต) ..."
  [ -x .venv/bin/python ] || "$PY" -m venv .venv || { echo "สร้าง .venv ไม่สำเร็จ"; read -p "กด Enter เพื่อปิด"; exit 1; }
  .venv/bin/python -m pip install --upgrade pip -q
  if ! .venv/bin/python -m pip install -r requirements.txt; then
    echo "ติดตั้งไลบรารีไม่สำเร็จ"; read -p "กด Enter เพื่อปิด"; exit 1
  fi
  touch .venv/.installed
  echo "ติดตั้งเสร็จแล้ว"
fi
echo "กำลังเปิด NetRemote ... (อย่าปิดหน้าต่างนี้ระหว่างใช้งาน)"
exec .venv/bin/python remote_desktop.py "$@"
