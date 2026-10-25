Unicode True

!ifndef VERSION
  !define VERSION "1.0.0"
!endif
!ifndef BIN_PATH
  !define BIN_PATH "..\..\dist\sentinel-net-windows-amd64.exe"
!endif

!include "MUI2.nsh"

Name "Sentinel Net ${VERSION}"
OutFile "..\..\dist\sentinel-net-setup-windows-amd64.exe"
InstallDir "$LOCALAPPDATA\Programs\SentinelNet"
InstallDirRegKey HKCU "Software\SentinelNet" "InstallDir"
RequestExecutionLevel user
BrandingText "Sentinel Net v${VERSION}"

!define MUI_ICON "..\..\assets\icon.ico"
!define MUI_UNICON "..\..\assets\icon.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\sentinel-net.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "gui"
!define MUI_FINISHPAGE_RUN_TEXT "Ouvrir la console graphique Sentinel Net"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "French"
!insertmacro MUI_LANGUAGE "English"

Section "Sentinel Net" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"

  File "/oname=sentinel-net.exe" "${BIN_PATH}"
  File "..\..\assets\icon.ico"
  File "..\..\README.md"
  File "..\..\LICENSE"

  WriteRegStr HKCU "Software\SentinelNet" "InstallDir" "$INSTDIR"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Start Menu and Desktop shortcuts
  CreateDirectory "$SMPROGRAMS\Sentinel Net"
  CreateShortCut "$SMPROGRAMS\Sentinel Net\Sentinel Net.lnk" "$INSTDIR\sentinel-net.exe" "gui" "$INSTDIR\icon.ico" 0
  CreateShortCut "$SMPROGRAMS\Sentinel Net\Uninstall Sentinel Net.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\icon.ico" 0
  CreateShortCut "$DESKTOP\Sentinel Net.lnk" "$INSTDIR\sentinel-net.exe" "gui" "$INSTDIR\icon.ico" 0

  ; Add install folder to current user PATH if missing
  ReadRegStr $0 HKCU "Environment" "Path"
  StrCmp $0 "" AddFreshPath CheckExistingPath

AddFreshPath:
  WriteRegExpandStr HKCU "Environment" "Path" "$INSTDIR"
  Goto BroadcastEnv

CheckExistingPath:
  Push $0
  Push "$INSTDIR"
  Call StrContains
  Pop $1
  StrCmp $1 "" 0 BroadcastEnv
  WriteRegExpandStr HKCU "Environment" "Path" "$0;$INSTDIR"

BroadcastEnv:
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=2000

  ; Windows Installed Apps registry entry
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet" "DisplayName" "Sentinel Net"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet" "Publisher" "Sentinel Net"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$DESKTOP\Sentinel Net.lnk"
  Delete "$SMPROGRAMS\Sentinel Net\Sentinel Net.lnk"
  Delete "$SMPROGRAMS\Sentinel Net\Uninstall Sentinel Net.lnk"
  RMDir "$SMPROGRAMS\Sentinel Net"

  Delete "$INSTDIR\sentinel-net.exe"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelNet"
  DeleteRegKey HKCU "Software\SentinelNet"
SectionEnd

Function StrContains
  Exch $R1 ; needle
  Exch
  Exch $R2 ; haystack
  Push $R3
  Push $R4
  Push $R5
  StrLen $R3 $R1
  StrLen $R4 $R2
  StrCpy $R5 0
  Loop:
    IntCmp $R5 $R4 NotFound 0 NotFound
    StrCpy $0 $R2 $R3 $R5
    StrCmp $0 $R1 Found
    IntOp $R5 $R5 + 1
    Goto Loop
  Found:
    StrCpy $R1 $0
    Goto Done
  NotFound:
    StrCpy $R1 ""
  Done:
    Pop $R5
    Pop $R4
    Pop $R3
    Pop $R2
    Exch $R1
FunctionEnd
