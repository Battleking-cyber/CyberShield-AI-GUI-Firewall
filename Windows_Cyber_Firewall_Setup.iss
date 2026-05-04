[Setup]
AppName=Windows Cyber Firewall
AppVersion=1.0
AppPublisher=Pankaj
DefaultDirName={pf}\Windows Cyber Firewall
OutputBaseFilename=Setup_Windows_Cyber_Firewall
SetupIconFile=firewall.ico
PrivilegesRequired=admin

[Files]
Source: "Windows_Cyber_Firewall.exe"; DestDir: "{app}"

[Icons]
Name: "{commondesktop}\Windows Cyber Firewall"; Filename: "{app}\Windows_Cyber_Firewall.exe"

[Run]
Filename: "{app}\Windows_Cyber_Firewall.exe"; Flags: nowait postinstall skipifsilent
