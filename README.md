# NetRemote — Remote Desktop

ดูหน้าจอ + ควบคุมเมาส์/คีย์บอร์ด + รับ-ส่งไฟล์ + แชท/โทร ด้วย ID 9 หลัก — เชื่อมต่อผ่าน Relay Server (หรือต่อตรงเมื่อทำได้) เข้ารหัส TLS ต้นทางถึงปลายทาง

## โครงสร้างโฟลเดอร์
```
Remote Desktop/
├── Client/                     ← โปรแกรม NetRemote (ติดตั้งบนเครื่องผู้ใช้)
│   ├── remote_desktop.py       โค้ดโปรแกรม
│   ├── requirements.txt        ไลบรารีที่ต้องใช้
│   ├── Run on Mac.command      เปิดโปรแกรมจาก source (ครั้งแรกติดตั้งไลบรารีใน .venv ให้เอง)
│   ├── Run on Windows.bat
│   ├── .env / .env.example     ตั้งค่าโปรแกรม (RELAY_ADDR, RELAY_KEY ฯลฯ) — .env ไม่ขึ้น GitHub
│   ├── assets/                 ไอคอน
│   └── packaging/              สคริปต์ Build .app / .dmg / ตัวติดตั้ง Windows + เซ็นชื่อ
├── Server/                     ← Relay Server + หน้าเว็บมอนิเตอร์ (รันบนเครื่อง Server)
│   ├── relay_server.py
│   ├── requirements.txt        ไลบรารีเสริม (psutil — ไม่บังคับ)
│   ├── start_server.sh / .bat  เปิด / reload / ปิด Server บน Mac·Linux / Windows (activate .venv ให้เอง)
│   ├── .env / .env.example     ตั้งค่า Server (พอร์ต, RELAY_KEY, รหัสหน้าเว็บ) — .env ไม่ขึ้น GitHub
│   ├── updates/                ไฟล์อัปเดตที่แจกให้ Client (ไม่ขึ้น GitHub)
│   ├── netremote-relay.service ติดตั้งเป็น service บน Linux
│   └── README.md               อธิบายการทำงานของ Server ทั้งหมด
├── docs/                       คู่มือการใช้งาน, วิธี Build
└── .github/workflows/          Build Windows / macOS อัตโนมัติเมื่อ push (เฉพาะเมื่อ Client เปลี่ยน)
```

## ดาวน์โหลดโปรแกรม
แท็บ **Actions** → **Build Windows** / **Build macOS** รายการล่าสุดที่มี ✓ → หัวข้อ **Artifacts**
- `NetRemote-Windows-Setup` → `NetRemote-Setup-<เวอร์ชัน>.exe`
- `NetRemote-macOS` → `NetRemote-macOS-<เวอร์ชัน>-arm64.dmg`

เลขเวอร์ชัน = `VERSION` ใน `Client/remote_desktop.py` + จำนวน commit (เช่น 1.7.30) — เพิ่มเองทุกครั้งที่ push

## เริ่มใช้งาน
1. **Server**: `cd Server && ./start_server.sh` — สร้าง .venv + ติดตั้งไลบรารีให้เอง แล้วเปิดเบื้องหลัง · `./start_server.sh reload` = ปิดแล้วเปิดใหม่ · อ่านค่าจาก `Server/.env` อัตโนมัติ
   หน้ามอนิเตอร์ `http://localhost:5911` · รายละเอียดใน [`Server/README.md`](Server/README.md)
2. **Client**: ใส่ `RELAY_ADDR` และ `RELAY_KEY` (ตรงกับ `Server/.env`) ในไฟล์ `Client/.env`
3. เครื่องที่ถูกควบคุม: แจ้ง ID + รหัสผ่าน · เครื่องที่ควบคุม: ใส่ ID + รหัสผ่าน → เชื่อมต่อ

## Build บนเครื่อง
- **macOS:** ดับเบิลคลิก `Client/packaging/Build macOS (.app).command` → `Network tools/Apps/macOS/`
- **Windows:** ดับเบิลคลิก `Client/packaging/Build Windows Installer.bat` → `Network tools\Apps\Windows\NetRemote-Setup-<เวอร์ชัน>.exe`

## Build พร้อมฝังการตั้งค่า
- วางไฟล์ `Client/.env` ไว้แล้ว Build → ค่า Server ถูกฝังในโปรแกรม (ผู้ใช้ไม่ต้องตั้งค่า)
- GitHub Actions: ตั้ง Repository secrets `NETREMOTE_RELAY_ADDR` และ `NETREMOTE_RELAY_KEY`
