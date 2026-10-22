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

[UninstallRun]
; ปิดโปรแกรมที่เปิดค้างอยู่ก่อนถอนการติดตั้ง
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM NetRemote.exe"; Flags: runhidden; RunOnceId: "CloseNetRemote"

[Code]
{ ---------------------------------------------------------------------------
  ถ้าติดตั้งไว้แล้ว: หน้าแรกให้เลือก  Modify (แก้ตัวเลือก) / Repair (ติดตั้งไฟล์ใหม่) / Remove (ถอนการติดตั้ง)
  ติดตั้งแบบเงียบ (อัปเดตอัตโนมัติ) จะข้ามหน้านี้
  --------------------------------------------------------------------------- }
const
  UninstKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{6E7B2C1A-4D3F-4B8E-9A61-2F5C0D8E7A31}_is1';

var
  ModePage: TInputOptionWizardPage;
  Installed: Boolean;
  OldVersion, UninstallCmd: String;
  QuitNow: Boolean;

function ShouldLaunch(): Boolean;
var
  i: Integer;
begin
  Result := True;
  for i := 1 to ParamCount do
    if CompareText(ParamStr(i), '/NOLAUNCH') = 0 then
      Result := False;
end;

function ReadUninst(Name: String; var Value: String): Boolean;
begin
  Result := RegQueryStringValue(HKCU, UninstKey, Name, Value) or
            RegQueryStringValue(HKLM, UninstKey, Name, Value);
end;

procedure InitializeWizard();
var
  first: String;
begin
  Installed := ReadUninst('UninstallString', UninstallCmd);
  if not ReadUninst('DisplayVersion', OldVersion) then
    OldVersion := '?';
  if Installed and not WizardSilent then
  begin
    ModePage := CreateInputOptionPage(wpWelcome,
      'NetRemote ' + OldVersion + ' is already installed',
      'What would you like to do?',
      'Choose an option, then click Next.', True, False);
    if OldVersion <> '{#AppVersion}' then
      first := 'Update / Modify - install version {#AppVersion} and change options (desktop icon, start with Windows)'
    else
      first := 'Modify - change options (desktop icon, start with Windows)';
    ModePage.Add(first);
    ModePage.Add('Repair - reinstall the program files (keeps your settings)');
    ModePage.Add('Remove - uninstall NetRemote from this computer');
    ModePage.SelectedValueIndex := 0;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if Installed and not WizardSilent and (ModePage <> nil) then
  begin
    if (ModePage.SelectedValueIndex = 1) and
            ((PageID = wpSelectDir) or (PageID = wpSelectTasks) or (PageID = wpSelectProgramGroup)) then
      Result := True;                       { Repair: ใช้ตัวเลือกเดิมทั้งหมด }
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  rc: Integer;
begin
  Result := True;
  if (ModePage <> nil) and (CurPageID = ModePage.ID) and (ModePage.SelectedValueIndex = 2) then
  begin
    Result := False;
    if Exec(RemoveQuotes(UninstallCmd), '', '', SW_SHOW, ewWaitUntilTerminated, rc) then
    begin
      QuitNow := True;
      WizardForm.Close;
    end
    else
      MsgBox('Could not start the uninstaller: ' + SysErrorMessage(rc), mbError, MB_OK);
  end;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if QuitNow then
    Confirm := False;                       { ปิดตัวติดตั้งหลังถอนการติดตั้งแล้ว โดยไม่ถามซ้ำ }
end;
