@echo off
rem Windows: builds a standalone "ST2110 AES67 Stream Viewer.exe" into dist\
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
    py -3 -m venv .venv || python -m venv .venv
    .venv\Scripts\pip install --quiet sounddevice
)
.venv\Scripts\pip install --quiet pyinstaller
.venv\Scripts\pyinstaller --noconfirm --windowed --onefile --name "ST2110 AES67 Stream Viewer" aes67_pcap_to_wav.py
echo.
echo Done: dist\ST2110 AES67 Stream Viewer.exe
pause
