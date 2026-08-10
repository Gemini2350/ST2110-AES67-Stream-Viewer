# Mac App Store – Schritt für Schritt

## 1. Einmalige Vorbereitung

1. **Apple Developer Program** beitreten: <https://developer.apple.com/programs/>
   (99 $/Jahr; als Einzelperson reicht die Apple-ID).
2. **Xcode installieren** (App Store), einmal starten, unter
   *Settings → Accounts* mit der Apple-ID anmelden.
3. Dort *Manage Certificates…* → zwei Zertifikate anlegen:
   - **Apple Distribution**
   - **Mac Installer Distribution**
4. Auf <https://developer.apple.com/account> unter *Identifiers* eine
   **App-ID** anlegen: Bundle-ID explizit, z. B. `ch.simplexity.st2110viewer`
   (muss zur `BUNDLE_ID` im Build-Skript passen). Capability: App Sandbox
   ist bei Mac-Apps implizit, nichts weiter anhaken.
5. Unter *Profiles* ein **Provisioning Profile** vom Typ **Mac App Store**
   für diese App-ID erzeugen, herunterladen und als
   `appstore.provisionprofile` in diesen Ordner legen.
6. In **App Store Connect** (<https://appstoreconnect.apple.com>) unter
   *Meine Apps* → „+" die App anlegen: Name „ST 2110 / AES67 PCAP Stream
   Viewer" (muss store-weit frei sein), Plattform macOS, Bundle-ID wählen,
   SKU frei (z. B. `st2110viewer`).

## 2. Build & Upload

```bash
export IDENTITY_APP="Apple Distribution: Dein Name (TEAMID)"
export IDENTITY_PKG="3rd Party Mac Developer Installer: Dein Name (TEAMID)"
export VERSION=1.0.0
./build_appstore.command
```

(Die exakten Zertifikatsnamen zeigt `security find-identity -v -p codesigning`.)

Ergebnis: `dist/ST2110 AES67 Stream Viewer.pkg` → mit der **Transporter**-App
(Mac App Store, kostenlos) hochladen. Nach ~15 min taucht der Build in
App Store Connect unter *TestFlight/Builds* auf.

Ohne gesetzte Identitäten macht das Skript einen **Trockenlauf**
(Ad-hoc-Signatur, kein .pkg) – gut zum lokalen Testen des sandboxed Builds.

## 3. Store-Eintrag ausfüllen

- **Screenshots**: mind. 1 Stück, erlaubte Größen u. a. 2560×1600 oder
  2880×1800 (einfach Fenster groß ziehen, ⇧⌘4 + Leertaste).
- **Beschreibung/Keywords**: AES67, ST 2110, PCAP, RTP, Jitter, …
- **Datenschutz**: „Daten werden nicht erhoben" (die App hat kein Netzwerk).
- **Export Compliance**: keine eigene Verschlüsselung → Standardfragen mit
  „Nein" beantworten (`ITSAppUsesNonExemptEncryption` ist schon gesetzt).
- **App-Review-Notizen**: unbedingt erwähnen, dass die App PCAP-Dateien
  analysiert, und den Prüfern eine Testdatei geben – `sample_capture.pcap`
  aus diesem Ordner irgendwo hochladen (z. B. GitHub/iCloud-Link) und den
  Link in die Notizen schreiben. Sonst kann der Reviewer nichts sehen.
- Altersfreigabe 4+, Kategorie *Dienstprogramme*.

Dann **Zur Prüfung einreichen**. Review dauert typisch 1–3 Werktage.
Optional vorher mit **TestFlight** auf dem eigenen Mac testen.

## 4. Besonderheiten dieses Builds

- **App Sandbox ist aktiv** (Store-Pflicht): Dateien öffnet die App nur noch
  über die Dateidialoge (das gewährt der Sandbox den Zugriff). Drag & Drop
  auf CLI-Art bzw. Start mit Pfad-Argument funktioniert im Store-Build nicht
  für beliebige Pfade.
- **Kein FFmpeg-Aufruf**: Die Sandbox verbietet das Starten externer
  Programme; JPEG-XS-Streams werden erkannt, analysiert und als .jxs
  exportiert, aber nicht als Bild dekodiert. (Eingebauter Decoder: siehe
  SVT-JPEG-XS-Abschnitt im README bzw. Patent-/Lizenzfrage klären.)
- **Architektur**: Der Build entsteht auf Apple Silicon als arm64-only.
  Intel-Macs abzudecken erfordert einen Universal2-Build mit dem
  python.org-Python (nicht Homebrew) – oder man akzeptiert arm64-only,
  der Store filtert dann auf kompatible Macs.
- Version hochzählen: `VERSION=1.0.1 ./build_appstore.command`, neu
  hochladen, neuen Build im Store-Eintrag auswählen.
