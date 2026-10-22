#!/bin/bash
# =====================================================================
#  Build "NetRemote.app" สำหรับ macOS — ดับเบิลคลิกไฟล์นี้บน Mac
#  ผลลัพธ์: Network tools/Apps/macOS/NetRemote.app และไฟล์ .dmg
# =====================================================================
cd "$(dirname "$0")"
PKG="$(pwd)"
APPDIR="$(cd .. && pwd)"
ROOT="$(cd ../.. && pwd)"
OUT="$ROOT/Apps/macOS"
WORK="$PKG/.work"
ARCH="$(uname -m)"
NAME="NetRemote"
SRC="$APPDIR/remote_desktop.py"
ICON="$APPDIR/assets/netremote.icns"

pause() { echo; read -p "กด Enter เพื่อปิดหน้าต่างนี้"; }
fail() { echo; echo "❌ $1"; pause; exit 1; }

echo "=============================================="
echo "  Build $NAME.app  (macOS $ARCH)"
echo "=============================================="
[ -f "$SRC" ] || fail "ไม่พบไฟล์ $SRC"

# 1) หา Python ที่มี tkinter (แนะนำ Python จาก python.org)
PY=""
for v in 3.14 3.13 3.12 3.11 3.10 3.9; do
  p="/Library/Frameworks/Python.framework/Versions/$v/bin/python3"
  if [ -x "$p" ] && "$p" -c "import tkinter" 2>/dev/null; then PY="$p"; break; fi
done
if [ -z "$PY" ]; then
  for p in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    if [ -x "$p" ] && "$p" -c "import tkinter" 2>/dev/null; then PY="$p"; break; fi
  done
fi
[ -n "$PY" ] || fail "ไม่พบ Python 3 ที่มี tkinter — ติดตั้งจาก https://www.python.org/downloads/macos/"
TKV="$("$PY" -c 'import tkinter; print(tkinter.TkVersion)')"
echo "ใช้ Python : $PY  ($("$PY" -V 2>&1), Tk $TKV)"
if [ "$TKV" = "8.5" ]; then
  echo "⚠  Tk 8.5 (รุ่นเก่าของ Apple) หน้าตาโปรแกรมอาจเพี้ยน — แนะนำติดตั้ง Python จาก python.org"
fi

# 2) เครื่องมือ Build (venv แยกไว้ใน packaging/.work)
VENV="$WORK/venv-$ARCH-$("$PY" -c 'import sys; print("%d%d" % sys.version_info[:2])')"
if [ ! -x "$VENV/bin/python" ]; then
  echo "กำลังเตรียมเครื่องมือ Build (ครั้งแรก 1-3 นาที ต้องต่ออินเทอร์เน็ต) ..."
  "$PY" -m venv "$VENV" || fail "สร้าง venv ไม่สำเร็จ"
fi
V="$VENV/bin/python"
"$V" -m pip install -q --upgrade pip
"$V" -m pip install -q --upgrade pyinstaller mss Pillow pynput cryptography sounddevice numpy opencv-python-headless tkinterdnd2 || fail "ติดตั้งเครื่องมือไม่สำเร็จ (ตรวจสอบอินเทอร์เน็ต)"

# 3) Build  (ถ้ามีไฟล์ .env จะฝังไปกับโปรแกรม — ผู้ใช้ไม่ต้องตั้งค่า Relay เอง)
ADD_ENV=()
if [ -f "$APPDIR/.env" ]; then
  ADD_ENV=(--add-data "$APPDIR/.env:.")
  echo "🔐 ฝังไฟล์ .env (ตั้งค่า Relay) ไปกับโปรแกรม"
fi
echo; echo "▶ กำลัง Build $NAME.app ..."
"$V" -m PyInstaller --noconfirm --clean --windowed --log-level WARN \
  --distpath "$WORK/dist" --workpath "$WORK/build" --specpath "$WORK" \
  --name "$NAME" --icon "$ICON" --osx-bundle-identifier com.networktools.netremote --hidden-import pynput.keyboard._darwin --hidden-import pynput.mouse._darwin "${ADD_ENV[@]}" \
  "$SRC" || fail "Build ไม่สำเร็จ"

# 3.1) ขอสิทธิ์ไมโครโฟน/กล้อง (แชทโทรเสียง/วีดีโอคอล) — ถ้าไม่มี macOS จะปิดโปรแกรมทันทีที่เปิดไมค์/กล้อง
PLIST="$WORK/dist/$NAME.app/Contents/Info.plist"
/usr/bin/plutil -replace NSMicrophoneUsageDescription -string "NetRemote ใช้ไมโครโฟนสำหรับโทรเสียงและวีดีโอคอล" "$PLIST"
/usr/bin/plutil -replace NSCameraUsageDescription -string "NetRemote ใช้กล้องสำหรับวีดีโอคอล" "$PLIST"
/usr/bin/codesign --force --deep -s - "$WORK/dist/$NAME.app" 2>/dev/null

# 4) คัดลอกไปที่ Apps/macOS + สร้าง .dmg
mkdir -p "$OUT"
rm -rf "$OUT/$NAME.app"
ditto "$WORK/dist/$NAME.app" "$OUT/$NAME.app" || fail "คัดลอกไม่สำเร็จ"
DMG="$OUT/$NAME-macOS-$ARCH.dmg"
STAGE="$WORK/dmg"; rm -rf "$STAGE"; mkdir -p "$STAGE"
ditto "$OUT/$NAME.app" "$STAGE/$NAME.app"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "$NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null && echo "สร้าง $DMG แล้ว"

echo
echo "✅ เสร็จแล้ว:  $OUT/$NAME.app"
read -p "ติดตั้งลงโฟลเดอร์ Applications ด้วยเลยไหม? (y/n) " ans
if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
  rm -rf "/Applications/$NAME.app"
  ditto "$OUT/$NAME.app" "/Applications/$NAME.app" && echo "ติดตั้งที่ /Applications/$NAME.app แล้ว"
  echo "หมายเหตุ: Build ใหม่อาจต้องให้สิทธิ์ใน System Settings > Privacy & Security ใหม่"
fi
open "$OUT"
pause
