@echo off
rem Windows launcher: creates a local venv with sounddevice (for playback) on first run.
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
    echo Erster Start: richte Python-Umgebung ein ...
    py -3 -m venv .venv || python -m venv .venv
    .venv\Scripts\pip install --quiet sounddevice
)
start "" .venv\Scripts\pythonw.exe aes67_pcap_to_wav.py %*
