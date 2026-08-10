#!/bin/bash
# macOS launcher: creates a local venv with sounddevice (for playback) on first run.
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    echo "Erster Start: richte Python-Umgebung ein ..."
    python3 -m venv .venv || exit 1
    ./.venv/bin/pip install --quiet sounddevice || \
        echo "Note: could not install 'sounddevice' - playback disabled, export still works."
fi
exec ./.venv/bin/python aes67_pcap_to_wav.py "$@"
