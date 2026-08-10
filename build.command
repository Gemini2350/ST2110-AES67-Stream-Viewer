#!/bin/bash
# macOS: builds a standalone "ST2110 AES67 Stream Viewer.app" into dist/
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
    ./.venv/bin/pip install --quiet sounddevice
fi
./.venv/bin/pip install --quiet pyinstaller
[ -f icon.icns ] || ./.venv/bin/python make_icon.py
./.venv/bin/pyinstaller --noconfirm --windowed --name "ST2110 AES67 Stream Viewer" \
    --icon icon.icns --osx-bundle-identifier ch.simplexity.st2110viewer \
    aes67_pcap_to_wav.py
xattr -cr "dist/ST2110 AES67 Stream Viewer.app"
codesign --force --deep -s - "dist/ST2110 AES67 Stream Viewer.app"
echo
echo "Done: dist/ST2110 AES67 Stream Viewer.app"
open dist
