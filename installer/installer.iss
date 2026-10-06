; ============================================================================
; Lili enterprise NET — Script de Instalación Oficial (Inno Setup)
; ============================================================================

#define MyAppName "Lili enterprise NET"
#define MyAppVersion "0.1.9"
#define MyAppPublisher "Lili enterprise NET"
#define MyAppURL "https://github.com/fabian300806/RemoteDeskCustom"
#define MyAppExeName "Lili-Enterprise-NET.exe"

[Setup]
AppId={{E6F7A9B1-28C3-49F1-9A84-18D2B4459C72}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=Lili-Enterprise-NET-Setup-v{#MyAppVersion}
SetupIconFile=..\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Ejecutable principal (renombrado a Lili-Enterprise-NET.exe para presentación formal)
Source: "..\target\release\lantern_scan.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion
; Copia con nombre lantern_scan.exe para garantizar retrocompatibilidad absoluta
Source: "..\target\release\lantern_scan.exe"; DestDir: "{app}"; DestName: "lantern_scan.exe"; Flags: ignoreversion
; Generador de licencias corporativas
Source: "..\target\release\keygen.exe"; DestDir: "{app}"; Flags: ignoreversion
; Recursos e Iconos
Source: "..\assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\logo.png"; DestDir: "{app}"; Flags: ignoreversion
; Scripts auxiliares
Source: "..\Iniciar-Lili-enterprise-NET.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Generar-Licencias.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\Generar-Licencias.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{autoprograms}\{#MyAppName}\Generador de Licencias"; Filename: "{app}\keygen.exe"; IconFilename: "{app}\icon.ico"
Name: "{autoprograms}\{#MyAppName}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
