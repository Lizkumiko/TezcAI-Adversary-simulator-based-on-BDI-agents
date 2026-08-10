#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Filename:  credAgR.py
# Version: 1.0.0
#
# Descripción: Acciones del agente reactivo de acceso por credenciales (credAgR).
#              MITRE ATT&CK: TA0006 Credential Access (T1110 Brute Force).
#
# Alcance deliberado (por seguridad, definido junto con el usuario):
#   - Solo opera contra hosts/puertos ya descubiertos en services.json (no
#     escanea nada nuevo, no expande el alcance por su cuenta).
#   - Lista de credenciales corta y curada (no diccionarios masivos).
#   - Se detiene en la primera credencial válida por servicio.
#   - HTTP: solo intenta si el servicio ya exige autenticación (401 Basic Auth).
#   - SSH: si falla la conexión (no solo la autenticación), no insiste con el host.
#
# cred_scan: recorre services.json y prueba credenciales por defecto contra
#            los servicios HTTP, SSH y MQTT encontrados. Los hallazgos se
#            reportan en tiempo real vía events.finding() y se guardan en
#            credentials.json.
#
# ================================================================================================

import json
import threading
import time
import uuid

import paho.mqtt.client as mqtt
import paramiko
import requests
import urllib3

import events

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AGENT = "credAgR"

# Acciones .ev_* (reporte de inicio/resultado) ya ligadas al nombre de este agente.
actions = events.make_reactive_actions(AGENT)

# Credenciales por defecto, curadas y acotadas a propósito (ver nota de alcance arriba).
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "user"),
    ("guest", "guest"),
]

HTTPS_PORTS = {443, 8443, 9443}
SSH_PORT = 22
MQTT_PORT = 1883
REQUEST_TIMEOUT = 3
ATTEMPT_DELAY = 0.2

MITRE_BRUTE_FORCE = {"tactic": "TA0006", "technique": "T1110"}
MITRE_ACTIVE_SCANNING = {"tactic": "TA0043", "technique": "T1595"}
MITRE_DEFAULT_ACCOUNTS = {"tactic": "TA0006", "technique": "T1078.001"}

# Rutas comunes de APIs REST y paneles de gestión (estilo dirb, curado y
# acotado a propósito: no es un diccionario masivo, solo la superficie más
# habitual de API managers, paneles admin y frameworks de gestión).
COMMON_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/login", "/api/auth", "/api/token",
    "/api/users", "/api/status", "/api/health", "/api/docs",
    "/swagger.json", "/swagger-ui.html", "/openapi.json", "/graphql",
    "/actuator", "/actuator/health", "/actuator/env",
    "/login", "/admin", "/management", "/rest", "/v1", "/v2",
    "/status", "/health", "/config",
]

# Esquemas de campos JSON más comunes en logins de APIs REST. No sabemos de
# antemano qué convención usa cada API real, así que se prueban todos contra
# el mismo endpoint (sigue siendo una lista curada y acotada, no fuzzing).
JSON_LOGIN_FIELD_SETS = [
    ("username", "password"),
    ("email", "password"),
    ("user", "pass"),
]


def _test_http_creds(ip, port, service):
    """Prueba credenciales HTTP Basic Auth. Solo si el servicio ya exige
    autenticación (401 sin credenciales); si no, se omite para no arrojar
    falsos positivos contra paneles que siempre responden 200."""
    scheme = "https" if (port in HTTPS_PORTS or "https" in service) else "http"
    url = f"{scheme}://{ip}:{port}/"

    try:
        baseline = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
    except requests.RequestException as e:
        print(f"[!] No se pudo contactar {url}: {e}")
        return None, scheme

    if baseline.status_code != 401:
        print(f"[*] {url} no exige autenticación HTTP Basic (status {baseline.status_code}), se omite")
        return None, scheme

    for user, pwd in DEFAULT_CREDS:
        try:
            r = requests.get(url, auth=(user, pwd), timeout=REQUEST_TIMEOUT, verify=False)
        except requests.RequestException:
            continue
        if r.status_code != 401:
            return (user, pwd), scheme
        time.sleep(ATTEMPT_DELAY)

    return None, scheme


def _discover_endpoints(ip, port, scheme):
    """Enumera COMMON_API_PATHS sobre un servicio HTTP ya descubierto (estilo
    dirb). Antes compara contra una ruta inexistente para descartar servidores
    que responden igual a todo (falso positivo tipo soft-404)."""
    base = f"{scheme}://{ip}:{port}"

    try:
        baseline = requests.get(f"{base}/__tezcai_{uuid.uuid4().hex}", timeout=REQUEST_TIMEOUT, verify=False)
        baseline_signature = (baseline.status_code, len(baseline.content))
    except requests.RequestException as e:
        print(f"[!] No se pudo contactar {base} para descubrir endpoints: {e}")
        return []

    encontrados = []
    for path in COMMON_API_PATHS:
        try:
            r = requests.get(f"{base}{path}", timeout=REQUEST_TIMEOUT, verify=False)
        except requests.RequestException:
            continue

        if r.status_code == 404 or (r.status_code, len(r.content)) == baseline_signature:
            continue

        encontrados.append({"path": path, "status": r.status_code, "length": len(r.content)})
        time.sleep(ATTEMPT_DELAY)

    return encontrados


def _test_api_login(url):
    """Prueba credenciales por defecto contra un endpoint tipo login/API,
    probando los esquemas de campo JSON más comunes (JSON_LOGIN_FIELD_SETS)
    ya que no se conoce de antemano la convención de la API real. Solo
    intenta si la respuesta sin credenciales ya sugiere que el endpoint
    exige autenticación."""
    try:
        baseline = requests.post(url, json={}, timeout=REQUEST_TIMEOUT, verify=False)
    except requests.RequestException:
        return None

    if baseline.status_code not in (400, 401, 403):
        return None

    for field_user, field_pass in JSON_LOGIN_FIELD_SETS:
        for user, pwd in DEFAULT_CREDS:
            try:
                r = requests.post(
                    url, json={field_user: user, field_pass: pwd},
                    timeout=REQUEST_TIMEOUT, verify=False,
                )
            except requests.RequestException:
                continue
            if r.status_code != baseline.status_code and r.status_code in (200, 201, 302):
                return (user, pwd)
            time.sleep(ATTEMPT_DELAY)

    return None


def _test_ssh_creds(ip, port):
    """Prueba credenciales SSH. Si la conexión falla a nivel de transporte
    (no de autenticación), se aborta el host en vez de seguir insistiendo."""
    for user, pwd in DEFAULT_CREDS:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                ip, port=port, username=user, password=pwd,
                timeout=REQUEST_TIMEOUT, banner_timeout=REQUEST_TIMEOUT, auth_timeout=REQUEST_TIMEOUT,
                look_for_keys=False, allow_agent=False,
            )
            return (user, pwd)
        except paramiko.AuthenticationException:
            time.sleep(ATTEMPT_DELAY)
            continue
        except Exception as e:
            print(f"[!] No se pudo conectar a {ip}:{port} vía SSH: {e}")
            return None
        finally:
            client.close()

    return None


def _mqtt_connect_attempt(ip, port, user, pwd):
    """Un solo intento de CONNECT MQTT. Devuelve True si el broker acepta
    (CONNACK con reason code 0), sin importar si hubo credenciales o no."""
    accepted = threading.Event()
    result = {"ok": False}

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    if user:
        client.username_pw_set(user, pwd)

    def on_connect(_client, _userdata, _flags, reason_code, _properties=None):
        result["ok"] = (reason_code == 0)
        accepted.set()

    client.on_connect = on_connect

    try:
        client.connect(ip, port=port, keepalive=REQUEST_TIMEOUT)
    except Exception as e:
        print(f"[!] No se pudo conectar a {ip}:{port} vía MQTT: {e}")
        return False

    client.loop_start()
    accepted.wait(REQUEST_TIMEOUT)
    client.loop_stop()
    client.disconnect()
    return result["ok"]


def _test_mqtt_creds(ip, port):
    """Prueba primero conexión anónima (sin usuario/contraseña) contra un
    broker MQTT ya descubierto; si el broker la exige, prueba credenciales
    por defecto. La ausencia total de autenticación es en sí un hallazgo
    (broker mal configurado), no una credencial adivinada."""
    if _mqtt_connect_attempt(ip, port, None, None):
        return ("", "", True)

    for user, pwd in DEFAULT_CREDS:
        if _mqtt_connect_attempt(ip, port, user, pwd):
            return (user, pwd, False)
        time.sleep(ATTEMPT_DELAY)

    return None


@actions.add_function(".cred_scan", (str,))
def cred_scan(target):
    """
    Prueba credenciales por defecto contra los servicios HTTP/SSH ya
    descubiertos en services.json. Parámetro: IP de un target o "all".
    """
    print("[*] Iniciando prueba de credenciales por defecto...")

    try:
        with open("services.json", "r") as f:
            services_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("[!] No se encontró services.json válido. Ejecuta service_scanning primero.")
        return False

    if target.lower() != "all":
        services_data = [h for h in services_data if h.get("ip") == target]

    hallazgos = []
    endpoints_encontrados = []

    for host in services_data:
        ip = host.get("ip")
        for port_info in host.get("protocols", {}).get("tcp", []):
            if port_info.get("state") != "open":
                continue

            port = port_info.get("port")
            service = (port_info.get("service") or "").lower()

            if service == "ssh" or port == SSH_PORT:
                print(f"[*] Probando credenciales SSH por defecto en {ip}:{port}")
                found = _test_ssh_creds(ip, port)
                if found:
                    user, pwd = found
                    hallazgo = {"ip": ip, "port": port, "protocol": "ssh", "path": "", "user": user, "password": pwd}
                    hallazgos.append(hallazgo)
                    events.finding(
                        AGENT,
                        f"[{AGENT}] Credencial válida: {user}:{pwd} en ssh://{ip}:{port}",
                        mitre=MITRE_BRUTE_FORCE,
                        detection_hint=(
                            f"Hasta {len(DEFAULT_CREDS)} intentos de login SSH fallidos contra el mismo host "
                            "en pocos segundos, seguidos de uno exitoso — en auth.log/sshd se ve como ráfaga "
                            "de 'Failed password' + 'Accepted password' desde el mismo origen."
                        ),
                        **hallazgo,
                    )
                else:
                    print(f"[*] Sin credenciales por defecto válidas en {ip}:{port}")
                continue

            if service == "mqtt" or port == MQTT_PORT:
                print(f"[*] Probando acceso MQTT en {ip}:{port}")
                found = _test_mqtt_creds(ip, port)
                if found:
                    user, pwd, anonimo = found
                    hallazgo = {"ip": ip, "port": port, "protocol": "mqtt", "path": "", "user": user, "password": pwd}
                    hallazgos.append(hallazgo)
                    if anonimo:
                        events.finding(
                            AGENT,
                            f"[{AGENT}] Broker MQTT acepta conexiones anónimas en mqtt://{ip}:{port}",
                            mitre=MITRE_DEFAULT_ACCOUNTS,
                            detection_hint=(
                                "CONNECT sin usuario/contraseña aceptado (CONNACK 0) — en logs de Mosquitto "
                                "se ve como 'New client connected' sin fase de autenticación previa; revisar "
                                "'allow_anonymous' en la configuración del broker."
                            ),
                            **hallazgo,
                        )
                    else:
                        events.finding(
                            AGENT,
                            f"[{AGENT}] Credencial válida: {user}:{pwd} en mqtt://{ip}:{port}",
                            mitre=MITRE_BRUTE_FORCE,
                            detection_hint=(
                                f"Hasta {len(DEFAULT_CREDS)} intentos de CONNECT con usuario/contraseña "
                                "rechazados (CONNACK 'not authorized') antes de uno aceptado — visible en "
                                "logs del broker como ráfaga de conexiones rechazadas desde el mismo origen."
                            ),
                            **hallazgo,
                        )
                else:
                    print(f"[*] Sin acceso MQTT válido en {ip}:{port}")
                continue

            if "http" not in service and "soap" not in service:
                continue

            print(f"[*] Probando credenciales HTTP por defecto en {ip}:{port}")
            found, scheme = _test_http_creds(ip, port, service)
            if found:
                user, pwd = found
                hallazgo = {"ip": ip, "port": port, "protocol": scheme, "path": "/", "user": user, "password": pwd}
                hallazgos.append(hallazgo)
                events.finding(
                    AGENT,
                    f"[{AGENT}] Credencial válida: {user}:{pwd} en {scheme}://{ip}:{port}/",
                    mitre=MITRE_BRUTE_FORCE,
                    detection_hint=(
                        f"Hasta {len(DEFAULT_CREDS)} respuestas 401 consecutivas contra la misma URL en "
                        "pocos segundos, seguidas de un 200 — en el access log del servidor web se ve como "
                        "ráfaga corta de auth fallida desde el mismo origen."
                    ),
                    **hallazgo,
                )
            else:
                print(f"[*] Sin credenciales por defecto válidas en {ip}:{port}")

            print(f"[*] Descubriendo endpoints de API en {ip}:{port}")
            descubiertos = _discover_endpoints(ip, port, scheme)
            for ep in descubiertos:
                endpoint_hallazgo = {"ip": ip, "port": port, "protocol": scheme, **ep}
                endpoints_encontrados.append(endpoint_hallazgo)
                events.finding(
                    AGENT,
                    f"[{AGENT}] Endpoint expuesto: {scheme}://{ip}:{port}{ep['path']} (status {ep['status']})",
                    mitre=MITRE_ACTIVE_SCANNING,
                    detection_hint=(
                        f"Ráfaga de hasta {len(COMMON_API_PATHS)} solicitudes GET a rutas distintas en pocos "
                        "segundos desde el mismo origen, muchas devolviendo 404 — patrón típico de un "
                        "dirb/gobuster que suele confundirse con errores normales de la aplicación."
                    ),
                    **endpoint_hallazgo,
                )

                if not any(k in ep["path"].lower() for k in ("login", "auth", "token")):
                    continue

                api_url = f"{scheme}://{ip}:{port}{ep['path']}"
                api_found = _test_api_login(api_url)
                if api_found:
                    user, pwd = api_found
                    hallazgo = {
                        "ip": ip, "port": port, "protocol": scheme, "path": ep["path"],
                        "user": user, "password": pwd,
                    }
                    hallazgos.append(hallazgo)
                    events.finding(
                        AGENT,
                        f"[{AGENT}] Credencial de API válida: {user}:{pwd} en {api_url}",
                        mitre=MITRE_BRUTE_FORCE,
                        detection_hint=(
                            f"Hasta {len(DEFAULT_CREDS)} POST con 400/401/403 contra el mismo endpoint en "
                            "pocos segundos, seguidos de un 200/201/302 — en logs de la API se ve como "
                            "ráfaga de intentos de login fallidos desde el mismo origen antes de uno exitoso."
                        ),
                        **hallazgo,
                    )

    try:
        with open("credentials.json", "w") as f:
            json.dump(hallazgos, f, indent=2)
    except IOError as e:
        print(f"[!] Error guardando credentials.json: {e}")

    try:
        with open("endpoints.json", "w") as f:
            json.dump(endpoints_encontrados, f, indent=2)
    except IOError as e:
        print(f"[!] Error guardando endpoints.json: {e}")

    print(
        f"[+] Prueba de credenciales completada. Hallazgos: {len(hallazgos)}. "
        f"Endpoints descubiertos: {len(endpoints_encontrados)}"
    )
    return True
