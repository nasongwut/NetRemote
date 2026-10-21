# NetRemote — Remote Desktop

ดูหน้าจอ + ควบคุมเมาส์/คีย์บอร์ด + รับ-ส่งไฟล์ ด้วย ID 9 หลัก — **เชื่อมต่อผ่าน Relay Server เท่านั้น** เข้ารหัส TLS ต้นทางถึงปลายทาง

## ดาวน์โหลดโปรแกรม (.exe / .dmg)
แท็บ **Actions** → เลือกรายการ Build ล่าสุดที่มี ✓ → หัวข้อ **Artifacts**
- `NetRemote-Windows` → `NetRemote.exe`
- `NetRemote-macOS` → `.dmg` (Mac ชิป Apple Silicon)

## ไฟล์ในโฟลเดอร์นี้
| ไฟล์ / โฟลเดอร์ | หน้าที่ |
|---|---|
| `remote_desktop.py` | โค้ดโปรแกรม NetRemote |
| `requirements.txt` | ไลบรารีที่ต้องใช้ (mss, Pillow, pynput, cryptography) |
| `Run on Mac.command` / `Run on Windows.bat` | เปิดโปรแกรม (ครั้งแรกติดตั้งไลบรารีให้อัตโนมัติใน `.venv`) |
| `assets/` | ไอคอนโปรแกรม |
| `packaging/` | สคริปต์ Build เป็น `.app` (macOS) และ `.exe` (Windows) |
| `docs/คู่มือการใช้งาน.txt` | คู่มือการใช้งาน |
| `relay/` | Relay Server + หน้าเว็บมอนิเตอร์ — อธิบายการทำงานใน [`relay/README.md`](relay/README.md) |
| `.env` / `.env.example` | ตั้งค่าฝั่งโปรแกรม (RELAY_ADDR, RELAY_KEY ฯลฯ) — `.env` ไม่ขึ้น GitHub |
| `relay/.env` / `relay/.env.example` | ตั้งค่าฝั่ง Relay Server (พอร์ต, RELAY_KEY, หน้ามอนิเตอร์) |
| `.github/workflows/build.yml` | Build `.exe` / `.dmg` อัตโนมัติทุกครั้งที่ push |

## Build บนเครื่อง
- **macOS:** ดับเบิลคลิก `packaging/Build macOS (.app).command` → `../Apps/macOS/NetRemote.app` + `.dmg`
- **Windows:** ดับเบิลคลิก `packaging/Build Windows (.exe).bat` → `..\Apps\Windows\NetRemote.exe`

## เริ่มใช้งาน
1. **Relay Server** (ครั้งเดียว): `cd relay && python3 relay_server.py` — อ่านค่าจาก `relay/.env` อัตโนมัติ
   หน้ามอนิเตอร์ `http://localhost:5911` · อธิบายการทำงานทั้งหมดใน [`relay/README.md`](relay/README.md)
2. **ตั้งค่าโปรแกรม**: ใส่ `RELAY_ADDR` ในไฟล์ `.env` (RELAY_KEY ตรงกับ relay/.env แล้ว)
3. เครื่องที่ถูกควบคุม: แท็บ "ให้เครื่องอื่นควบคุมเครื่องนี้" → เริ่มเปิดรับ → แจ้ง ID + รหัสผ่าน
4. เครื่องที่ควบคุม: ใส่ ID + รหัสผ่าน → เชื่อมต่อ

## Build พร้อมฝังการตั้งค่า
- วางไฟล์ `.env` ไว้แล้ว Build → ค่า Relay ถูกฝังใน `.app` / `.exe` (ผู้ใช้ไม่ต้องตั้งค่า)
- GitHub Actions: ตั้ง Repository secrets `NETREMOTE_RELAY_ADDR` และ `NETREMOTE_RELAY_KEY`
  (Settings → Secrets and variables → Actions) แล้ว Build จะฝังค่าให้อัตโนมัติ
