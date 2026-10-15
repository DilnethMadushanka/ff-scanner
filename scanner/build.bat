@echo off
REM Builds FFScanner.exe (single portable file) on a Windows PC.
REM Needs Python 3.9+ from python.org (tick "Add Python to PATH" when installing).
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller || goto :err
python -m PyInstaller --onefile --console --uac-admin --name FFScanner ^
  --add-data "signatures.json;." ff_scanner.py || goto :err
copy /y signatures.json dist\signatures.json >nul
echo.
echo Done. Your program is in the "dist" folder:
echo   dist\FFScanner.exe
echo   dist\signatures.json   (edit this to add new hack names)
pause
exit /b 0
:err
echo Build failed. Check that Python is installed and on PATH.
pause
exit /b 1
