# เซ็นชื่อดิจิทัล (Authenticode) ให้ไฟล์ .exe / .dll / .pyd ทุกไฟล์ที่ยังไม่มีลายเซ็น
# ใช้ใน GitHub Actions:  pwsh packaging/sign_windows.ps1 <โฟลเดอร์หรือไฟล์> ...
#
# ต้องตั้ง Repository secrets (Settings > Secrets and variables > Actions):
#   WINDOWS_CERT_PFX_BASE64  = ไฟล์ใบรับรอง .pfx แปลงเป็น base64
#   WINDOWS_CERT_PASSWORD    = รหัสผ่านของ .pfx
# ถ้ายังไม่ได้ตั้ง → ข้ามการเซ็น (build ต่อได้ตามปกติ)
#
# หมายเหตุ: ใบรับรองแบบเซ็นผ่านคลาวด์ (เช่น SSL.com eSigner, DigiCert KeyLocker) ไม่มีไฟล์ .pfx
#           ให้เปลี่ยนคำสั่ง signtool ในฟังก์ชัน Sign-File เป็นเครื่องมือของผู้ออกใบรับรองนั้น
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Paths)
$ErrorActionPreference = "Stop"

if (-not $env:WINDOWS_CERT_PFX_BASE64) {
    Write-Host "No signing certificate configured - skipping code signing."
    exit 0
}

$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
if (-not $signtool) { throw "signtool.exe not found" }

$pfx = Join-Path $env:RUNNER_TEMP "codesign.pfx"
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:WINDOWS_CERT_PFX_BASE64))

function Sign-File([string]$f) {
    & $signtool.FullName sign /f $pfx /p $env:WINDOWS_CERT_PASSWORD /fd SHA256 `
        /tr "http://timestamp.digicert.com" /td SHA256 /q $f
    if ($LASTEXITCODE -ne 0) { throw "signing failed: $f" }
}

try {
    $files = foreach ($p in $Paths) {
        if (Test-Path $p -PathType Container) {
            Get-ChildItem $p -Recurse -File -Include *.exe, *.dll, *.pyd
        } else { Get-Item $p }
    }
    $n = 0
    foreach ($f in $files) {
        if ((Get-AuthenticodeSignature $f.FullName).Status -ne "Valid") {   # ไฟล์ที่เซ็นมาแล้ว (เช่น python312.dll) ไม่ต้องเซ็นซ้ำ
            Sign-File $f.FullName
            $n++
        }
    }
    Write-Host "Signed $n file(s)."
} finally {
    Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}
