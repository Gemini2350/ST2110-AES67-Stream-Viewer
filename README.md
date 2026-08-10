# ST 2110 / AES67 PCAP Stream Viewer

![build](https://github.com/Gemini2350/ST2110-AES67-Stream-Viewer/actions/workflows/build.yml/badge.svg)

**Downloads:** Fertige Builds für macOS (Apple Silicon + Intel) und Windows
entstehen automatisch per GitHub Actions – bei jedem Release unter
[Releases](https://github.com/Gemini2350/ST2110-AES67-Stream-Viewer/releases),
Zwischenstände als Artifacts der [Action-Läufe](https://github.com/Gemini2350/ST2110-AES67-Stream-Viewer/actions).

Grafisches Tool, das AES67-Audio- und ST-2110-Video-Streams aus
`.pcap`/`.pcapng`-Mitschnitten (z. B. aus Wireshark) extrahiert:

- Listet alle erkannten Streams nach **Multicast-Adresse**, Port, SSRC und Payload Type
- **Audio (AES67 / 2110-30/-31):** Format-Erkennung (L16/L24, Kanäle, Samplerate,
  übersteuerbar), **Export als WAV**, **Wiedergabe** mit Play/Pause und Zeitbalken
- **Video unkomprimiert (2110-20, RFC 4175):** Auflösung/Framerate werden aus den
  Payload-Headern erkannt, Frame-Vorschau mit Scrubbing-Balken, Export als **PNG**
  (Sampling wählbar: YCbCr 4:2:2 10/8 bit, RGB 8 bit)
- **JPEG XS (2110-22 / IPMX, RFC 9134):** Erkennung inkl. Auflösung aus dem
  Picture Header, Export der Frames als **.jxs**-Codestreams; Vorschau/PNG
  zusätzlich, wenn ein FFmpeg mit JPEG-XS-Decoder installiert ist
- **Analyse** pro Stream (Audio und Video): Paketverlust anhand der
  RTP-Sequenznummern (Ereignisliste mit Zeitpunkt und Anzahl), Jitter nach
  RFC 3550, Paketabstands-Statistik und Zeitverlaufs-Graph
- **PTP-Vergleich:** Enthält der Mitschnitt PTP-Sync/Follow_Up-Messages
  (UDP 319/320 oder Layer 2), wird die Grandmaster-Zeit rekonstruiert und
  pro Stream der Versatz der RTP-Timestamps zur PTP-Uhr gemessen
  (Median/σ/Drift in ppm + Verlaufskurve) – zeigt sofort, ob ein Sender
  PTP-gelockt ist
- Paketverluste werden angezeigt und beim Export/Abspielen mit Stille aufgefüllt,
  umsortierte Pakete werden korrekt einsortiert (RTP-Sequenz/-Timestamp)

Läuft auf **macOS und Windows** (und Linux), Python ≥ 3.9 mit tkinter.

## Starten

- **macOS:** Doppelklick auf `run.command` (oder `./run.command` im Terminal).
  Beim ersten Start wird automatisch eine lokale Python-Umgebung mit `sounddevice`
  (für die Wiedergabe) angelegt.
- **Windows:** Doppelklick auf `run.bat`.
- **Direkt:** `python3 aes67_pcap_to_wav.py` – ohne das Paket `sounddevice`
  ist nur die Wiedergabe deaktiviert, der Export funktioniert immer.

Falls tkinter fehlt (Homebrew-Python): `brew install python-tk`

## Kommandozeile

```
python3 aes67_pcap_to_wav.py capture.pcap --list
python3 aes67_pcap_to_wav.py capture.pcap --export 1 out.wav [--bits 24] [--channels 2] [--rate 48000]
python3 aes67_pcap_to_wav.py capture.pcap --analyze 1   # Verlust-/Jitter-Analyse
python3 aes67_pcap_to_wav.py capture.pcap --export-frames 3 frames/ [--frames 0-24] [--sampling 422-10]
```

## Eigenständige App bauen (One-Click, ohne Python)

PyInstaller kann nicht cross-kompilieren: die `.app` auf einem Mac bauen,
die `.exe` auf einem Windows-Rechner.

- **macOS:** Doppelklick auf `build.command` → `dist/ST2110 AES67 Stream Viewer.app` (~28 MB).
  Das Skript erledigt auch `xattr -cr` + Ad-hoc-`codesign` (ohne das verweigert
  macOS den Start). Manuell:

  ```
  ./.venv/bin/pip install pyinstaller
  ./.venv/bin/pyinstaller --noconfirm --windowed --name "ST2110 AES67 Stream Viewer" aes67_pcap_to_wav.py
  xattr -cr "dist/ST2110 AES67 Stream Viewer.app" && codesign --force --deep -s - "dist/ST2110 AES67 Stream Viewer.app"
  ```

- **Windows:** Python von python.org installieren (Häkchen „Add to PATH"),
  dann Doppelklick auf `build.bat` → `dist/ST2110 AES67 Stream Viewer.exe`. Manuell:

  ```
  py -3 -m venv .venv
  .venv\Scripts\pip install sounddevice pyinstaller
  .venv\Scripts\pyinstaller --noconfirm --windowed --onefile --name "ST2110 AES67 Stream Viewer" aes67_pcap_to_wav.py
  ```

**Mac App Store:** kompletter Ablauf in [APPSTORE.md](APPSTORE.md)
(`build_appstore.command` baut den sandboxed, signierten Store-Build als .pkg).

Hinweise zum Weitergeben an andere:

- **macOS:** Die Ad-hoc-Signatur reicht für den eigenen Rechner. Auf fremden Macs
  blockt Gatekeeper heruntergeladene Apps → einmalig Rechtsklick → „Öffnen"
  (oder `xattr -cr` auf die App). Sauber lösbar nur mit Apple-Developer-Zertifikat
  + Notarisierung. Apple-Silicon-Build läuft nicht auf Intel-Macs und umgekehrt.
- **Windows:** SmartScreen warnt bei unsignierten heruntergeladenen EXEs →
  „Weitere Informationen" → „Trotzdem ausführen".

## Hinweise

- AES67 überträgt Kanalzahl/Bittiefe nicht im Stream selbst (das steht im SDP).
  Das Tool rät anhand von Paketgröße und RTP-Timestamps; bei mehrdeutigen Fällen
  (z. B. 6 Bytes/Frame = L24 stereo *oder* L16 3-Kanal) wird L24 bevorzugt,
  über die Format-Auswahl lässt sich das korrigieren.
- Unterstützt IPv4/UDP (Ethernet, VLAN-Tags, Linux cooked capture, Loopback).
- Unicast-RTP-Streams werden ebenfalls erkannt (Haken „nur Multicast" entfernen).
- 2110-20: Sampling steht nicht im Stream (nur im SDP) – Standardannahme ist
  YCbCr 4:2:2 10 bit (BT.709). Interlaced-Streams werden nicht deinterlaced
  (Felder landen im selben Bild).
- JPEG XS: Dekodieren erfordert FFmpeg mit JPEG-XS-Unterstützung
  (z. B. Build mit SVT-JPEG-XS). Ohne FFmpeg werden .jxs-Codestreams
  exportiert, die sich extern dekodieren lassen.
- HDCP-verschlüsselte IPMX-Streams können prinzipbedingt nicht ausgewertet werden.
