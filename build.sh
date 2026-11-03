#!/bin/sh

set -e
cd "$(dirname "$0")"
python3 -m pip install --quiet pyinstaller
python3 -m PyInstaller --onefile --clean --noconfirm --name eid --add-data "data:data" eid.py
rm -rf build eid.spec
echo "Done: dist/eid"
