# Mac App Store — step by step

## 1. One-time setup

1. Join the **Apple Developer Program**: <https://developer.apple.com/programs/>
   ($99/year; an Apple ID is enough for individuals).
2. **Install Xcode** (App Store), launch it once, sign in with your Apple ID
   under *Settings → Accounts*.
3. There, *Manage Certificates…* → create two certificates:
   - **Apple Distribution**
   - **Mac Installer Distribution**
4. On <https://developer.apple.com/account> under *Identifiers* create an
   **App ID**: explicit bundle ID, e.g. `ch.simplexity.st2110viewer`
   (must match `BUNDLE_ID` in the build script). App Sandbox is implicit
   for Mac apps, nothing else to tick.
5. Under *Profiles* create a **provisioning profile** of type **Mac App Store**
   for this App ID, download it and place it in this folder as
   `appstore.provisionprofile`.
6. In **App Store Connect** (<https://appstoreconnect.apple.com>) under
   *My Apps* → "+" create the app: name "ST 2110 / AES67 PCAP Stream Viewer"
   (must be unique store-wide), platform macOS, select the bundle ID,
   SKU freely chosen (e.g. `st2110viewer`).

## 2. Build & upload

```bash
export IDENTITY_APP="Apple Distribution: Your Name (TEAMID)"
export IDENTITY_PKG="3rd Party Mac Developer Installer: Your Name (TEAMID)"
export VERSION=1.0.0
./build_appstore.command
```

(`security find-identity -v -p codesigning` shows the exact certificate names.)

Result: `dist/ST2110 AES67 Stream Viewer.pkg` → upload with the **Transporter**
app (Mac App Store, free). After ~15 min the build shows up in
App Store Connect under *TestFlight/Builds*.

Without the identities set, the script performs a **dry run**
(ad-hoc signature, no .pkg) — useful for testing the sandboxed build locally.

## 3. Store listing

- **Screenshots**: at least 1, allowed sizes include 2560×1600 or
  2880×1800 (enlarge the window, ⇧⌘4 + space).
- **Description/keywords**: AES67, ST 2110, PCAP, RTP, jitter, PTP, …
- **Privacy**: "Data not collected" (the app has no networking).
- **Export compliance**: no own encryption → answer the standard questions
  with "No" (`ITSAppUsesNonExemptEncryption` is already set).
- **App review notes**: do mention that the app analyzes PCAP files, and give
  the reviewers a test file — generate one with `make_test_pcap.py`, upload it
  somewhere (GitHub/iCloud link) and put the link in the notes. Otherwise the
  reviewer has nothing to look at.
- Age rating 4+, category *Utilities*.

Then **Submit for review**. Review typically takes 1–3 business days.
Optionally test via **TestFlight** on your own Mac first.

## 4. Specifics of this build

- **App Sandbox is enabled** (store requirement): the app opens files only
  through the file dialogs (which grant sandbox access). Launching with a
  path argument does not work for arbitrary paths in the store build.
- **No FFmpeg invocation**: the sandbox forbids launching external programs;
  JPEG XS streams are detected, analyzed and exported as .jxs, but not
  decoded to images. The app shows built-in instructions for decoding
  externally. (Built-in decoder: see the SVT-JPEG-XS notes in the README,
  and clarify the patent/licensing questions first.)
- **Architecture**: built on Apple Silicon this is arm64-only. Covering
  Intel Macs requires a universal2 build with the python.org Python
  (not Homebrew) — or accept arm64-only; the store then filters for
  compatible Macs.
- Version bumps: `VERSION=1.0.1 ./build_appstore.command`, upload again,
  select the new build in the store listing.
