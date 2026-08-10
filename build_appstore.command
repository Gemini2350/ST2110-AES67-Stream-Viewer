#!/bin/bash
# Mac App Store build: sandboxed, signed, packaged as .pkg for upload.
#
# Required beforehand (see APPSTORE.md):
#   IDENTITY_APP="Apple Distribution: Your Name (TEAMID)"
#   IDENTITY_PKG="3rd Party Mac Developer Installer: Your Name (TEAMID)"
#   optional: BUNDLE_ID, VERSION, appstore.provisionprofile in this folder
#
# Without IDENTITY_* this performs a dry run with an ad-hoc signature (no .pkg).
set -e
cd "$(dirname "$0")"

APP_NAME="ST2110 AES67 Stream Viewer"
BUNDLE_ID="${BUNDLE_ID:-ch.simplexity.st2110viewer}"
VERSION="${VERSION:-1.0.0}"
IDENTITY_APP="${IDENTITY_APP:-}"
IDENTITY_PKG="${IDENTITY_PKG:-}"
PROFILE="${PROFILE:-appstore.provisionprofile}"

if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
    ./.venv/bin/pip install --quiet sounddevice
fi
./.venv/bin/pip install --quiet pyinstaller
[ -f icon.icns ] || { ./.venv/bin/python make_icon.py; }

./.venv/bin/pyinstaller --noconfirm --windowed --name "$APP_NAME" \
    --icon icon.icns --osx-bundle-identifier "$BUNDLE_ID" aes67_pcap_to_wav.py

APP="dist/$APP_NAME.app"
PLIST="$APP/Contents/Info.plist"
pb() { /usr/libexec/PlistBuddy -c "Set :$1 $2" "$PLIST" 2>/dev/null || \
      /usr/libexec/PlistBuddy -c "Add :$1 $3 $2" "$PLIST"; }
pb CFBundleShortVersionString "$VERSION" string
pb CFBundleVersion "$VERSION" string
pb LSApplicationCategoryType public.app-category.utilities string
pb LSMinimumSystemVersion 11.0 string
pb NSHumanReadableCopyright "© $(date +%Y)" string
pb ITSAppUsesNonExemptEncryption false bool

if [ -f "$PROFILE" ]; then
    cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
    echo "Embedded provisioning profile: $PROFILE"
else
    echo "Note: no $PROFILE found (required for the store upload)"
fi

xattr -cr "$APP"
if [ -n "$IDENTITY_APP" ]; then
    SIGN="$IDENTITY_APP"; TS="--timestamp"
else
    echo "WARNING: IDENTITY_APP not set - dry run with ad-hoc signature"
    SIGN="-"; TS=""
fi
# sign all embedded binaries first, then frameworks, then the app itself
find "$APP/Contents" -type f \( -name "*.so" -o -name "*.dylib" \) \
    -exec codesign --force $TS -s "$SIGN" {} +
find "$APP/Contents/Frameworks" -maxdepth 1 -name "*.framework" \
    -exec codesign --force $TS -s "$SIGN" {} + 2>/dev/null || true
codesign --force $TS --entitlements entitlements.plist -s "$SIGN" "$APP"
codesign --verify --strict "$APP" && echo "Signature OK"

if [ -n "$IDENTITY_PKG" ]; then
    productbuild --component "$APP" /Applications \
        --sign "$IDENTITY_PKG" "dist/$APP_NAME.pkg"
    echo
    echo "Done: dist/$APP_NAME.pkg - upload it with the Transporter app."
else
    echo "IDENTITY_PKG not set - skipped .pkg (dry run)."
fi
