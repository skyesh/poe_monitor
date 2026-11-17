This Python project monitors IP cameras and power cycles their PoE port via SNMP if they stop responding to ping.

<img width="875" height="492" alt="image" src="https://github.com/user-attachments/assets/786ea511-79f1-4fcf-8a2d-b5ed1e4f0f5a" />

# PoE Monitor – wersja multi-switch dla HP 2620 / Proxmox LXC

## Co zawiera
- GUI do dodawania wielu switchy (SNMP v1/v2c, IP i community).
- Urządzenia przypisywane do switcha i portu.
- Potwierdzony na Twoim HP 2620 OID admin PoE: `1.3.6.1.2.1.105.1.1.1.3.1.PORT`.
- Ping dla Linuxa (`ping -n -c 1 -W 2`).
- Test SNMP, ręczny power cycle, log zdarzeń.
- SQLite; stara tabela `cameras` jest migrowana automatycznie.
- Monitoring starych wpisów jest po migracji WYŁĄCZONY, aby nie wywołać restartów bez zgody.

## 1. Wymagania (Debian LXC)
```bash
apt update
apt install -y python3 python3-venv python3-pip snmp iputils-ping
```

## 2. Kopia i podmiana plików
Zatrzymaj dotychczasową usługę, jeśli istnieje:
```bash
systemctl stop poe-monitor 2>/dev/null || true
cd /opt
cp -a poe_monitor poe_monitor.backup.$(date +%F-%H%M%S)
```
Rozpakuj archiwum na komputerze lub skopiuj jego zawartość do `/opt/poe_monitor`.
WAŻNE: zachowaj dotychczasowy plik `/opt/poe_monitor/cameras.db`. Nie zastępuj go pustą bazą.
W katalogu `/opt/poe_monitor` powinny być `poe_monitor.py`, `requirements.txt`, `templates/`, `poe-monitor.env.example`.

## 3. Konfiguracja logowania do GUI
```bash
cd /opt/poe_monitor
cp poe-monitor.env.example poe-monitor.env
nano poe-monitor.env
```
Ustaw własne, długie hasło `POE_WEB_PASSWORD` i losowy `POE_SECRET_KEY`.
Aplikacja nie uruchomi się, jeśli hasło pozostanie przykładowe.

## 4. Python i zależności
```bash
cd /opt/poe_monitor
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt
```

## 5. Test narzędzi i SNMP
```bash
command -v snmpget
command -v snmpset
snmpget -v2c -c public 10.10.5.168 1.3.6.1.2.1.1.1.0
```
Ostatnie polecenie jest przykładem z archiwum testowego; użyj swoich danych, jeśli uległy zmianie.

## 6. Instalacja usługi systemd
```bash
cp poe-monitor.service /etc/systemd/system/poe-monitor.service
systemctl daemon-reload
systemctl enable --now poe-monitor
systemctl status poe-monitor
journalctl -u poe-monitor -f
```
Panel: `http://IP_LXC:5000` (logowanie Basic Auth z `poe-monitor.env`).

## 7. Pierwsza konfiguracja
1. Zaloguj się do panelu.
2. Sprawdź przeniesiony switch (jego community nie jest wyświetlane).
3. Kliknij `Test SNMP`.
4. Dodaj urządzenie testowe albo sprawdź istniejący wpis.
5. Istniejące wpisy po migracji mają monitoring wyłączony. Włącz go dopiero po sprawdzeniu mapowania.
6. Wykonaj ręczny `Restart PoE` na niekrytycznym porcie.

## Zachowanie watchdog
- Domyślny interwał: 30 s.
- Domyślny próg: 5 kolejnych nieudanych pingów.
- PoE OFF: 10 s.
- Cooldown: 300 s.
- Maksymalnie 2 automatyczne restarty na urządzenie w godzinę.
- OID: `1.3.6.1.2.1.105.1.1.1.3.1.PORT`, porty 1–48.

## Ważne ograniczenia
- To wydanie jest przygotowane pod HP 2620-48-PoEP i indeksy portów 1–48, zgodnie z testem portu 27 dostarczonym przez użytkownika. Przed automatyzacją sprawdź kilka portów.
- Community SNMP jest przechowywane w SQLite jako zwykły tekst. Ogranicz dostęp do pliku `cameras.db` (domyślnie uruchamianie usługi jako root).
- Panel używa HTTP Basic Auth, ale ruch HTTP nie jest szyfrowany. Nie wystawiaj go do Internetu; najlepiej ogranicz dostęp firewallem do VLAN-u administracyjnego albo użyj reverse proxy z HTTPS.
- Ręczny restart jest dostępny także dla urządzeń z wyłączonym monitoringiem.
- Aplikacja nie jest certyfikowanym systemem wysokiej dostępności. Testuj na jednym porcie przed wdrożeniem produkcyjnym.
