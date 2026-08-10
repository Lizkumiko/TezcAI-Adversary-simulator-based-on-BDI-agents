# TezcAI — Adversary Simulator based on BDI Agents

Evolución del simulador de adversarios **Tezcatlipoca**, ahora con un enfoque basado en la automatización mediante **agentes inteligentes BDI** (Belief-Desire-Intention), implementados sobre la librería Python [`agentspeak`](https://github.com/niklasf/python-agentspeak) (estilo Jason/AgentSpeak).

TezcAI simula, de forma automatizada, las primeras fases de una kill chain de intrusión (reconocimiento → acceso por credenciales → acceso inicial) contra la red real donde corre, con cada paso mapeado a **MITRE ATT&CK** y retransmitido en vivo a un panel web.

> ⚠️ **Uso exclusivo en entornos autorizados.** TezcAI escanea la red real del host y prueba credenciales activamente. Solo debe ejecutarse en laboratorios propios o con autorización explícita del propietario de la red objetivo.

## Cómo funciona

Cada fase de la kill chain se modela con dos agentes que colaboran:

- **Agente BDI (coordinador)**: delibera sobre metas (`.asl`), decide qué hacer y en qué orden, y delega el trabajo concreto en su agente reactivo.
- **Agente reactivo (ejecutor)**: no delibera, solo ejecuta la acción que el BDI le pide (escanear, probar credenciales, etc.) y reporta el resultado como belief.

Cuando un BDI termina su fase, hace **handoff** al siguiente BDI de la cadena, que retoma el testigo. Todo el flujo (fases, objetivos, delegaciones, handoffs, beliefs, hallazgos) se emite en tiempo real por consola (coloreado por agente) y por WebSocket hacia el panel web.

```
agDiscovery  (recon)         → networkAgR
      │ handoff
      ▼
agCredAccess (cred access)   → credAgR
      │ handoff
      ▼
agInitialAccess (initial access) → initAgR
```

## Agentes implementados

| Fase | Agente BDI | Agente reactivo | MITRE ATT&CK | Descripción |
|---|---|---|---|---|
| Reconocimiento | `agDiscovery` | `networkAgR` | TA0007 Discovery (T1046, T1082, T1018...) | Identifica ubicación de red (`whoami`), descubre hosts activos, detecta SO y escanea servicios/puertos. |
| Acceso por credenciales | `agCredAccess` | `credAgR` | TA0006 Credential Access (T1110 Brute Force) | Prueba credenciales por defecto (curadas, no diccionarios masivos) contra los servicios HTTP/SSH/MQTT ya descubiertos. Se detiene en la primera credencial válida por servicio. |
| Acceso inicial | `agInitialAccess` | `initAgR` | TA0001 Initial Access (T1078 Valid Accounts) | Confirma acceso real (solo lectura: `id` por SSH o GET autenticado) con las credenciales válidas encontradas. No escribe ni ejecuta payloads. |

Cada agente sigue el mismo patrón de archivos: `<nombre>.asl` (plan BDI en AgentSpeak) + `<nombre>.py` (acciones Python que ese plan invoca).

### Alcance de seguridad (por diseño)

- Ningún agente reactivo escanea o prueba nada fuera de lo ya descubierto por la fase anterior (no hay expansión de alcance automática).
- Listas de credenciales cortas y curadas, no ataques de fuerza bruta masivos.
- Las verificaciones de acceso son de solo lectura, sin persistencia ni ejecución de payloads.
- Cada hallazgo incluye un `detection_hint`: el patrón de log/tráfico que ese hallazgo debería producir del lado defensor (SIEM/WAF/IDS), pensado para validar si un SOC lo detectó.

## Pendiente (roadmap)

Para completar la kill chain simulada faltan:

- `agPrivEsc` / reactivo — TA0004 Privilege Escalation (T1068, T1548, T1134, T1484)
- `agLateralMov` / reactivo — TA0008 Lateral Movement (T1021, T1550, T1080, T1570)
- `agRecon` (OSINT pre-ataque) — TA0043 Reconnaissance (T1595, T1592, T1589, T1590)

## Panel web en vivo

`web/index.html` es un panel estático que se conecta por WebSocket (`ws://localhost:8765`) y muestra en vivo las fases, delegaciones, handoffs y hallazgos de la simulación a medida que ocurren.

## Instalación

Requiere Python 3.9+ y el binario `nmap` instalado en el sistema.

```bash
./setup.sh
```

El script crea el virtualenv en `./venv`, instala `requirements.txt` y verifica que `nmap` esté disponible.

## Uso

```bash
source venv/bin/activate
sudo -E python agDiscover.py
```

Se requieren privilegios de root para la detección de SO (`nmap -O`) y algunas pruebas de red. Con la simulación corriendo, abre `web/index.html` en el navegador para ver el panel en vivo.

### Salidas generadas

- `network_info.json` — ubicación de red detectada (IP, máscara, gateway)
- `targets.json` / `results.json` — hosts descubiertos y resultados de escaneo
- `services.json` — puertos y servicios detectados por host
- `credentials.json` — credenciales por defecto válidas encontradas
- `access.json` — accesos confirmados en la fase de acceso inicial

## Stack

- [`py-agentspeak`](https://pypi.org/project/py-agentspeak/) — motor BDI (AgentSpeak)
- `python-nmap` — escaneo de red y servicios
- `paramiko` — SSH
- `paho-mqtt` — MQTT
- `requests` — HTTP
- `websockets` — retransmisión de eventos al panel web
- `colorama` — salida coloreada en consola
