#!/bin/bash
echo "============================================"
echo " Fraud IOC Tracker - Python Build (Mac)"
echo "============================================"

if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 not found. Install from https://python.org/"
    exit 1
fi

echo "[1/3] Installing dependencies..."
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then echo "ERROR: pip install failed"; exit 1; fi

echo ""
echo "[2/3] Building app..."
pyinstaller --noconfirm --onefile --windowed --name "Fraud IOC Tracker" --add-data "data_store.py:." --add-data "enrichment.py:." app.py
if [ $? -ne 0 ]; then echo "ERROR: Build failed"; exit 1; fi

echo ""
echo "[3/3] Done! Your app is in dist/"
ls -la dist/
