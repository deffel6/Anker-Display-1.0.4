# Anker Solix Display – ESP32-C3 Firmware

Web-Flasher für die Anker Solix Display Firmware (Version 1.0.4), basierend auf [ESP Web Tools](https://esphome.github.io/esp-web-tools/).

## Hardware

- ESP32-C3 (z.B. ESP32-2424S012)
- 1.28" GC9A01A Round Display, 240×240
- Anker Solix Cloud API Integration

## Neu in 1.0.4

- Passwort-Anzeige (Auge-Symbol) in allen Formularen – Tippfehler bei der Eingabe sofort sichtbar
- Bei falschem Anker-Login: Korrektur direkt im Browser über die angezeigte IP-Adresse (kein Neu-Flashen mehr nötig)
- GPIO9-Reset entfernt (im Gehäuse nicht zugänglich)

## Flashen

1. Repo per GitHub Pages veröffentlichen (Settings → Pages → Branch `main`, Ordner `/`)
2. Seite mit Chrome oder Edge öffnen (Web Serial API erforderlich)
3. Board per USB anschließen
4. "Firmware installieren" klicken, Port auswählen

## Firmware-Dateien

| Datei | Offset | Beschreibung |
|---|---|---|
| `anker_display_1_0_4.ino.bootloader.bin` | 0x0 | Bootloader |
| `anker_display_1_0_4.ino.partitions.bin` | 0x8000 | Partitionstabelle |
| `boot_app0.bin` | 0xe000 | OTA-Auswahl |
| `anker_display_1_0_4.ino.bin` | 0x10000 | Hauptprogramm |

Alternativ liegt unter `firmware/anker_display_1_0_4.ino.merged.bin` eine bereits zusammengeführte Komplettdatei (ab Offset 0x0).

## Ersteinrichtung

1. Nach dem Flashen startet das Display im Setup-Modus
2. Mit dem WLAN **Anker-Display-Setup** verbinden
3. Im Browser `192.168.4.1` öffnen
4. WLAN- und Anker-Zugangsdaten eingeben
5. Das Display zeigt danach eine IP-Adresse – diese im Heimnetz aufrufen und die Anlage auswählen

## Falscher Anker-Login?

Kein Problem: Das Display zeigt "Anker-Login falsch!" und eine IP-Adresse. Diese im Browser aufrufen und die Zugangsdaten korrigieren – kein Neu-Flashen erforderlich.
