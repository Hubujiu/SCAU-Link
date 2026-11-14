; Native per-user installer. No driver installation or authentication is run.
#ifndef AppVersion
  #error AppVersion is required; build with scripts/build_installer.py
#endif
#ifdef InstallerTest
  #define ProductId "SCAULink.InstallerTest.v1"
  #define ProductName "SCAU Link 安装测试"
  #define ProductMutex "Local\SCAULink.InstallerTest.v1"
  #define StartupKey "Software\SCAULink\InstallerTests\Run"
  #define StartupName "SCAULinkInstallerTest"
  #define OutputSuffix "-test"
#else
  #define ProductId "SCAULink.Desktop"
  #define ProductMutex "Local\SCAULink.Desktop.v1"
  #define StartupKey "Software\Microsoft\Windows\CurrentVersion\Run"
  #define StartupName "SCAULink"
  #ifdef PreviewRelease
    #define ProductName "SCAU Link 预览版"
    #define OutputSuffix "-preview"
  #else
    #define ProductName "SCAU Link"
    #define OutputSuffix ""
  #endif
#endif

[Setup]
AppId={#ProductId}
AppName={#ProductName}
AppVersion={#AppVersion}
AppVerName={#ProductName} {#AppVersion}
AppPublisher=SCAU Link
DefaultDirName={localappdata}\Programs\SCAU Link
DefaultGroupName={#ProductName}
UsePreviousAppDir=yes
AppendDefaultDirName=no
DisableDirPage=no
DisableProgramGroupPage=yes
DisableWelcomePage=no
DisableReadyPage=no
PrivilegesRequired=lowest
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.17763
AppMutex={#ProductMutex}
CloseApplications=no
RestartApplications=no
AllowNoIcons=yes
UninstallDisplayName={#ProductName}
UninstallDisplayIcon={app}\SCAU-Link.exe
UninstallFilesDir={app}\uninstall
SetupIconFile={#RepoRoot}\assets\app.ico
WizardStyle=modern light
WizardSizePercent=110,110
WizardImageFile={#RepoRoot}\assets\setup-sidebar.bmp
WizardSmallImageFile={#RepoRoot}\assets\setup-logo.bmp
WizardImageStretch=yes
ShowLanguageDialog=no
OutputDir={#OutputDir}
OutputBaseFilename=SCAU-Link-{#AppVersion}-Setup-x64{#OutputSuffix}
Compression=lzma2
SolidCompression=yes
VersionInfoVersion={#AppVersion}.0
VersionInfoDescription=SCAU Link 安装程序
VersionInfoProductName=SCAU Link
VersionInfoProductVersion={#AppVersion}
ChangesAssociations=no
ChangesEnvironment=no

[Languages]
Name: "zhcn"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Messages]
SelectDirLabel3=安装到：
SelectDirBrowseLabel=可输入路径，或点击“浏览”。
SelectTasksLabel2=快捷方式
FinishedHeadingLabel=安装完成
FinishedLabelNoIcons=SCAU Link 已安装。
FinishedLabel=SCAU Link 已安装。
SetupAppRunningError=请先退出正在运行的 SCAU Link，再继续安装。安装程序不会自动断开网络。
UninstallAppRunningError=请先退出正在运行的 SCAU Link，再卸载。

[Tasks]
Name: "startmenu"; Description: "开始菜单快捷方式"; GroupDescription: "快捷方式："
Name: "desktop"; Description: "桌面快捷方式"; GroupDescription: "快捷方式："; Flags: unchecked

[Files]
Source: "{#PayloadDir}\SCAU-Link.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\scau-auth.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\runtime\*.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\runtime\manifest.json"; DestDir: "{app}\docs"; DestName: "runtime-manifest.json"; Flags: ignoreversion
Source: "{#PayloadDir}\source.zip"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#PayloadDir}\verification.json"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#RepoRoot}\LICENSE"; DestDir: "{app}\docs"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "{#RepoRoot}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "{#RepoRoot}\third_party\inno-setup\LICENSE.txt"; DestDir: "{app}\docs"; DestName: "Inno-Setup-LICENSE.txt"; Flags: ignoreversion
Source: "{#RepoRoot}\docs\installer-README.txt"; DestDir: "{app}\docs"; DestName: "README.txt"; Flags: ignoreversion

#ifndef InstallerTest
[Icons]
Name: "{userprograms}\SCAU Link"; Filename: "{app}\SCAU-Link.exe"; WorkingDir: "{app}"; Tasks: startmenu
Name: "{userdesktop}\SCAU Link"; Filename: "{app}\SCAU-Link.exe"; WorkingDir: "{app}"; Tasks: desktop
#endif

[Run]
Filename: "{app}\SCAU-Link.exe"; WorkingDir: "{app}"; Description: "启动 SCAU Link"; Flags: nowait postinstall unchecked skipifsilent

[Code]
var
  DriverButton: TNewButton;

function HasCaptureDriver: Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll')) or
            FileExists(ExpandConstant('{sys}\wpcap.dll'));
end;

procedure DownloadDriver(Sender: TObject);
var
  ErrorCode: Integer;
begin
  ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL,
            ewNoWait, ErrorCode);
end;

procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel1.Caption := '安装 SCAU Link';
  WizardForm.WelcomeLabel2.Caption := '版本 {#AppVersion}' + #13#10 + 'Windows x64';
  DriverButton := TNewButton.Create(WizardForm);
  DriverButton.Parent := WizardForm.FinishedPage;
  DriverButton.Left := WizardForm.FinishedLabel.Left;
  DriverButton.Top := WizardForm.RunList.Top + ScaleY(44);
  DriverButton.Width := ScaleX(112);
  DriverButton.Height := ScaleY(28);
  DriverButton.Caption := '下载 Npcap';
  DriverButton.OnClick := @DownloadDriver;
  DriverButton.Visible := False;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then begin
    DriverButton.Visible := not HasCaptureDriver;
    if not HasCaptureDriver then
      WizardForm.FinishedLabel.Caption := '需要 Npcap 才能进行有线认证。';
  end;
end;

function StartupCommand: String;
begin
  Result := '"' + ExpandConstant('{app}\SCAU-Link.exe') + '" --startup';
end;

function RecognizedStartupCommand(Value: String): Boolean;
var
  Tail, FileName: String;
  ClosingQuote: Integer;
begin
  Result := False;
  if (Length(Value) < 2) or (Value[1] <> '"') then Exit;
  Tail := Copy(Value, 2, Length(Value) - 1);
  ClosingQuote := Pos('"', Tail);
  if ClosingQuote = 0 then Exit;
  FileName := Copy(Tail, 1, ClosingQuote - 1);
  Tail := Trim(Copy(Tail, ClosingQuote + 1, Length(Tail)));
  Result := (CompareText(ExtractFileName(FileName), 'SCAU-Link.exe') = 0) and
            (Tail = '--startup');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Value: String;
begin
  if CurStep = ssPostInstall then begin
    { Preserve the enabled state; only relocate this application's known command. }
    if RegQueryStringValue(HKCU, '{#StartupKey}', '{#StartupName}', Value) and
       RecognizedStartupCommand(Value) then
      RegWriteStringValue(HKCU, '{#StartupKey}', '{#StartupName}', StartupCommand);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Value: String;
begin
  if CurUninstallStep = usUninstall then begin
    { Never remove a startup entry belonging to a different portable copy. }
    if RegQueryStringValue(HKCU, '{#StartupKey}', '{#StartupName}', Value) and
       (CompareText(Value, StartupCommand) = 0) then
      RegDeleteValue(HKCU, '{#StartupKey}', '{#StartupName}');
  end;
  { Settings, captures and Windows credentials are deliberately never touched. }
end;
