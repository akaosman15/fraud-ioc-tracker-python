@echo off
echo ============================================
echo  Fraud IOC Tracker - Python Build (Windows)
echo ============================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Install from https://python.org/
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERROR: pip install failed
    pause
    exit /b 1
)

echo.
echo [2/3] Building executable...
pyinstaller --noconfirm --onefile --windowed --name "Fraud IOC Tracker" --add-data "data_store.py;." --add-data "enrichment.py;." app.py
if %errorlevel% neq 0 (
    echo ERROR: Build failed
    pause
    exit /b 1
)

echo.
echo [3/3] Done! Your .exe is in the dist/ folder
echo.
dir dist\*.exe
echo.
pause
