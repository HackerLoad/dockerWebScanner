# dockerWebScanner

Netzwerk-Scanner als Web-App mit interaktiver Bubble-Map. Zeigt alle Geräte im lokalen Netzwerk, deren offene Ports und Docker-Container-Ports.

## Features

- **Host Discovery** – findet alle aktiven Geräte im Subnetz
- **Port-Scan** – scannt die 200 häufigsten Ports pro Gerät
- **Docker-Ports** – liest laufende Container via Docker-Socket aus und kennzeichnet deren Ports separat
- **Bubble-Map** – interaktive D3.js-Visualisierung mit Zoom, Drag und Click-to-Details
- **Live-Updates** – Geräte erscheinen progressiv während des Scans

## Voraussetzungen

- Docker + Docker Compose

## Starten

```bash
# Subnetz ermitteln (macOS)
ipconfig getifaddr en0   # z.B. 192.168.1.45 → Subnetz: 192.168.1.0/24

# Starten mit eigenem Subnetz
SUBNET=192.168.1.0/24 docker compose up --build
```

Dann im Browser: **http://localhost:5001**

> **Hinweis:** Das Subnetz muss manuell gesetzt werden, da der Container auf macOS (Docker Desktop) kein direktes Host-Networking nutzt.

## Projektstruktur

```
.
├── app.py              # Flask-Backend: Scan-Logik, Docker-API, REST-Endpunkte
├── requirements.txt    # Python-Abhängigkeiten
├── Dockerfile
├── docker-compose.yml
└── static/
    └── index.html      # Frontend: D3.js Bubble-Map (Single-File)
```

## API-Endpunkte

| Methode | Pfad           | Beschreibung                        |
|---------|----------------|-------------------------------------|
| GET     | `/`            | Web-UI                              |
| POST    | `/api/scan`    | Scan starten (`{"subnet": "..."}`)  |
| GET     | `/api/status`  | Scan-Status und Fortschritt         |
| GET     | `/api/results` | Ergebnisse des letzten Scans        |
| GET     | `/api/docker`  | Laufende Docker-Container           |

## Bubble-Farben

| Farbe  | Bedeutung             |
|--------|-----------------------|
| Grün   | Diese Maschine        |
| Orange | Gateway / Router      |
| Lila   | Docker-Ports aktiv    |
| Blau   | Reguläres Gerät       |
