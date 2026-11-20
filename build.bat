@echo off
REM Builds MemWatch.exe using the built-in .NET Framework compiler.
REM No .NET SDK, NuGet, or internet required.
REM Pass "nopause" as the first argument to skip the final pause (scripted builds).

set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe

if not exist "%CSC%" (
  echo ERROR: csc.exe not found. .NET Framework 4.x is required ^(ships with Windows 10/11^).
  if /i not "%~1"=="nopause" pause
  exit /b 1
)

if exist "%~dp0MemWatch.exe" del "%~dp0MemWatch.exe"

"%CSC%" /nologo /target:winexe /optimize+ /out:"%~dp0MemWatch.exe" ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.Drawing.dll ^
  /reference:System.Management.dll ^
  /reference:System.Windows.Forms.dll ^
  "%~dp0MemWatch.cs"

if exist "%~dp0MemWatch.exe" (
  echo.
  echo BUILD OK -^> "%~dp0MemWatch.exe"
) else (
  echo.
  echo BUILD FAILED
)
if /i not "%~1"=="nopause" pause
