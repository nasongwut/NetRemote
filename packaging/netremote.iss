; ตัวติดตั้ง NetRemote สำหรับ Windows (Inno Setup 6)
; GitHub Actions สร้างให้อัตโนมัติ — หรือสั่งเอง:  iscc /DAppVersion=1.6 /DSourceDir=dist\NetRemote packaging\netremote.iss
;
; - ติดตั้งให้ผู้ใช้คนเดียว (ไม่ต้องใช้สิทธิ์ Admin) ที่ %LOCALAPPDATA%\Programs\NetRemote
;   → โปรแกรมอัปเดตตัวเองได้โดยไม่ต้องถามสิทธิ์
; - เลือกได้ตอนติดตั้ง: เปิดโปรแกรมอัตโนมัติตอนเปิดเครื่อง (ติ๊กไว้ให้แล้ว) — อัปเดตแบบเงียบจะจำค่าเดิม
; - อัปเดตแบบเงียบ:  NetRemote-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS [/NOLAUNCH]

#ifndef AppVersion
  #define AppVersion "0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\NetRemote"
#endif
#ifndef OutputDir
  #define OutputDir "..\installer"
#endif

[Setup]
AppId={{6E7B2C1A-4D3F-4B8E-9A61-2F5C0D8E7A31}
AppName=NetRemote
AppVersion={#AppVersion}
AppVerName=NetRemote {#AppVersion}
AppPublisher=Network Tools
VersionInfoVersion={#AppVersion}
DefaultDirName={autopf}\NetRemote
DefaultGroupName=NetRemote
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=NetRemote-Setup-{#AppVersion}
SetupIconFile=..\assets\netremote.ico
UninstallDisplayIcon={app}\NetRemote.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=force
RestartApplications=no
SetupMutex=NetRemoteSetupMutex

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startup"; Description: "Start NetRemote automatically when Windows starts (ready to accept connections)"; GroupDescription: "Startup:"

[Registry]
; เปิดอัตโนมัติตอนเข้าสู่ระบบ Windows (ย่อหน้าต่างไว้ แต่พร้อมให้รีโมทเข้ามา) — ถอนการติดตั้งแล้วลบให้เอง
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "NetRemote"; ValueData: """{app}\NetRemote.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: startup
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "NetRemote"; Flags: deletevalue; Tasks: not startup

[InstallDelete]
; ลบไฟล์ไลบรารีของเวอร์ชันเก่าก่อน กันไฟล์ค้างปนกัน
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\NetRemote"; Filename: "{app}\NetRemote.exe"
Name: "{autodesktop}\NetRemote"; Filename: "{app}\NetRemote.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NetRemote.exe"; Description: "{cm:LaunchProgram,NetRemote}"; Flags: nowait postinstall; Check: ShouldLaunch

[Code]
function ShouldLaunch(): Boolean;
var
  i: Integer;
begin
  Result := True;
  for i := 1 to ParamCount do
    if CompareText(ParamStr(i), '/NOLAUNCH') = 0 then
      Result := False;
end;
