#!/usr/bin/env bash
# =====================================================================
#  NetRemote Relay Server — เปิด / ปิด / Reload
#
#    ./start_server.sh            เปิด Server (ถ้าเปิดอยู่แล้ว → reload ให้: ปิดตัวเก่าแล้วเปิดใหม่)
#    ./start_server.sh reload     ปิดแล้วเปิดใหม่ (ใช้หลังแก้ .env หรืออัปเดต relay_server.py)
#    ./start_server.sh stop       ปิด Server
#    ./start_server.sh status     ดูว่าเปิดอยู่ไหม
#    ./start_server.sh log        ดู log สด ๆ (Ctrl+C เพื่อออก — Server ยังทำงานต่อ)
#    ./start_server.sh fg         เปิดแบบอยู่หน้าจอ Terminal (Ctrl+C = ปิด)
#
#  ครั้งแรก: สร้าง .venv แล้วติดตั้งไลบรารีจาก requirements.txt ให้เอง
#  ทุกครั้ง: activate .venv ก่อนรัน (ติดตั้งใหม่เฉพาะเมื่อ requirements.txt เปลี่ยน)
#  Server ทำงานเบื้องหลัง: ปิด Terminal ได้ — log อยู่ที่ server.log
# =====================================================================
cd "$(dirname "$0")"
PIDFILE=.server.pid
LOG=server.log
PY="${PYTHON:-python3}"

running_pid() {
  [ -f "$PIDFILE" ] || return 1
  local pid; pid=$(cat "$PIDFILE" 2>/dev/null)
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && ps -p "$pid" -o command= 2>/dev/null | grep -q relay_server.py && { echo "$pid"; return 0; }
  rm -f "$PIDFILE"; return 1
}

setup_venv() {
  if ! command -v "$PY" >/dev/null 2>&1; then
    echo "ไม่พบ python3 — ติดตั้ง Python 3.8+ ก่อน (macOS: python.org, Linux: sudo apt install python3 python3-venv)"; exit 1
  fi
  if [ -d .venv ] && ! .venv/bin/python -c "" >/dev/null 2>&1; then
    echo "▶ .venv เดิมใช้ไม่ได้ (เช่น ย้ายเครื่อง/อัปเดต Python) — สร้างใหม่ ..."
    rm -rf .venv
  fi
  if [ ! -x .venv/bin/python ]; then
    echo "▶ สร้าง .venv ..."
    "$PY" -m venv .venv || { echo "สร้าง .venv ไม่สำเร็จ (Linux: sudo apt install python3-venv)"; exit 1; }
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
  if [ ! -f .venv/.installed ] || [ requirements.txt -nt .venv/.installed ]; then
    echo "▶ ติดตั้งไลบรารีจาก requirements.txt ..."
    if python -m pip install -q --upgrade pip && python -m pip install -q -r requirements.txt; then
      touch .venv/.installed
    else
      echo "⚠ ติดตั้งไลบรารีไม่สำเร็จ — Server ยังรันได้ (หน้า Server Monitor แสดงข้อมูลน้อยลง)"
    fi
  fi
}

do_stop() {
  local pid
  if pid=$(running_pid); then
    echo "■ ปิด Server (PID $pid) ..."
    kill "$pid" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null
    rm -f "$PIDFILE"
    return 0
  fi
  return 1
}

do_start() {
  setup_venv
  echo "▶ เริ่ม NetRemote Relay Server (เบื้องหลัง) ..."
  nohup python relay_server.py "$@" >>"$LOG" 2>&1 &
  echo $! > "$PIDFILE"
  sleep 1.5
  if running_pid >/dev/null; then
    echo "✓ ทำงานแล้ว (PID $(cat "$PIDFILE")) — ดู log: ./start_server.sh log"
    tail -n 5 "$LOG"
  else
    echo "✗ เปิดไม่สำเร็จ — ดูสาเหตุด้านล่าง:"; tail -n 20 "$LOG"; exit 1
  fi
}

case "${1:-start}" in
  start)
    shift 2>/dev/null
    if do_stop; then echo "↻ Server เปิดอยู่แล้ว — reload ให้"; fi
    do_start "$@" ;;
  reload|restart)
    shift
    do_stop || echo "(Server ไม่ได้เปิดอยู่)"
    do_start "$@" ;;
  stop)
    do_stop || echo "Server ไม่ได้เปิดอยู่" ;;
  status)
    if pid=$(running_pid); then echo "● เปิดอยู่ (PID $pid)"; else echo "○ ปิดอยู่"; fi ;;
  log|logs)
    touch "$LOG"; tail -n 50 -f "$LOG" ;;
  fg)
    shift
    do_stop && echo "↻ ปิดตัวที่ทำงานเบื้องหลังอยู่ก่อน"
    setup_venv
    echo "▶ เริ่ม NetRemote Relay Server — กด Ctrl+C เพื่อปิด"
    exec python relay_server.py "$@" ;;
  *)
    sed -n '3,15p' "$0"; exit 1 ;;
esac
