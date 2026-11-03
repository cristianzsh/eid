@echo off

cd /d "%~dp0"
python -m pip install --quiet pyinstaller || exit /b 1
python -m PyInstaller --onefile --clean --noconfirm --name eid --icon "eid.ico" --add-data "data;data" eid.py || exit /b 1
rmdir /s /q build 2>nul
del /q eid.spec 2>nul
echo Done: dist\eid.exe
