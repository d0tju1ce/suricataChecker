@echo off
rem Builds SuricataChecker-<version>.exe (dotnet SDK, .NET Framework 4.8 target), copies it to the application folder and signs it.
rem The version comes from <Version> in SuricataChecker.csproj; older SuricataChecker*.exe copies in the application folder are removed.
rem Signing uses the certificate "CN=SuricataChecker Code Signing" from Cert:\CurrentUser\My (sign.ps1); skipped if it is not present.
setlocal
cd /d "%~dp0"
set VER=
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "(Select-String -LiteralPath SuricataChecker.csproj -Pattern '<Version>([\d.]+)</Version>').Matches[0].Groups[1].Value"`) do set VER=%%v
if "%VER%"=="" (echo Version not found in SuricataChecker.csproj & exit /b 1)
set EXE=SuricataChecker-%VER%.exe
dotnet build SuricataChecker.csproj -c Release -nologo -v q
if errorlevel 1 (echo Build FAILED & exit /b 1)
copy /y bin\Release\SuricataChecker.exe "..\%EXE%" >nul
if errorlevel 1 (echo Copy FAILED - is %EXE% running? & exit /b 1)
copy /y bin\Release\SuricataChecker.exe.config "..\%EXE%.config" >nul
rem remove the exe of other versions (and the unversioned name used before 1.2.0) so only one copy is left
for %%f in ("..\SuricataChecker.exe" "..\SuricataChecker-*.exe") do if exist "%%~f" if /i not "%%~nxf"=="%EXE%" (
    del /q "%%~f" 2>nul
    if exist "%%~f" (echo Warning: %%~nxf could not be removed - is it running?) else (del /q "%%~f.config" 2>nul & echo Removed old %%~nxf)
)
echo Build OK: %EXE%
powershell -NoProfile -ExecutionPolicy Bypass -File sign.ps1 -Version %VER%
if errorlevel 1 (echo Signing FAILED & exit /b 1)
