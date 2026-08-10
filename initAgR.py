#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Filename:  initAgR.py
# Version: 1.0.0
#
# Descripción: Acciones del agente reactivo de acceso inicial (initAgR).
#              MITRE ATT&CK: TA0001 Initial Access (T1078 Valid Accounts).
#
# Alcance deliberado (mismo criterio que credAgR):
#   - No prueba credenciales nuevas ni escanea nada: solo reutiliza lo que
#     credAgR ya encontró en credentials.json para confirmar pie de apoyo real.
#   - La verificación es de solo lectura: un comando inofensivo por SSH
#     ('id') o una petición GET autenticada por HTTP. Nada de escritura,
#     persistencia ni ejecución de payloads.
#
# initial_access: recorre credentials.json y confirma acceso real con cada
#                 credencial. Los accesos confirmados se reportan en tiempo
#                 real vía events.finding() y se guardan en access.json.
#
# ================================================================================================

import json
import threading

import paho.mqtt.client as mqtt
import paramiko
import requests
import urllib3

import events

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AGENT = "initAgR"

# Acciones .ev_* (reporte de inicio/resultado) ya ligadas al nombre de este agente.
actions = events.make_reactive_actions(AGENT)

REQUEST_TIMEOUT = 3
MITRE_VALID_ACCOUNTS = {"tactic": "TA0001", "technique": "T1078"}

# Mismos esquemas de campo que credAgR: no se sabe cuál usó la API real, así
# que se repiten todos hasta que uno confirme el acceso.
JSON_LOGIN_FIELD_SETS = [
    ("username", "password"),
    ("email", "password"),
    ("user", "pass"),
]


def _verify_ssh(ip, port, user, pwd):
    """Confirma acceso SSH ejecutando un comando de solo lectura ('id')."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip, port=port, username=user, password=pwd,
            timeout=REQUEST_TIMEOUT, banner_timeout=REQUEST_TIMEOUT, auth_timeout=REQUEST_TIMEOUT,
            look_for_keys=False, allow_agent=False,
        )
        _, stdout, _ = client.exec_command("id", timeout=REQUEST_TIMEOUT)
        salida = stdout.read().decode(errors="replace").strip()
        return True, salida[:200]
    except Exception as e:
        print(f"[!] No se pudo confirmar acceso SSH en {ip}:{port}: {e}")
        return False, ""
    finally:
        client.close()


def _verify_http(ip, port, protocol, path, user, pwd):
    """Confirma acceso HTTP repitiendo la petición autenticada. Si la
    credencial viene de un endpoint de API (path distinto de "/"), repite un
    login JSON probando los mismos esquemas de campo que credAgR (no se sabe
    cuál funcionó al momento de guardar la credencial)."""
    url = f"{protocol}://{ip}:{port}{path or '/'}"

    if path and path != "/":
        for field_user, field_pass in JSON_LOGIN_FIELD_SETS:
            try:
                r = requests.post(
                    url, json={field_user: user, field_pass: pwd},
                    timeout=REQUEST_TIMEOUT, verify=False,
                )
            except requests.RequestException as e:
                print(f"[!] No se pudo confirmar acceso HTTP en {url}: {e}")
                return False, ""
            if r.status_code not in (401, 403):
                return True, f"HTTP {r.status_code}, {len(r.content)} bytes"
        return False, ""

    try:
        r = requests.get(url, auth=(user, pwd), timeout=REQUEST_TIMEOUT, verify=False)
    except requests.RequestException as e:
        print(f"[!] No se pudo confirmar acceso HTTP en {url}: {e}")
        return False, ""

    if r.status_code not in (401, 403):
        evidencia = f"HTTP {r.status_code}, {len(r.content)} bytes"
        return True, evidencia
    return False, ""


def _verify_mqtt(ip, port, user, pwd):
    """Confirma acceso MQTT repitiendo el CONNECT (con credenciales, o sin
    ninguna si el acceso original fue anónimo)."""
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
        print(f"[!] No se pudo confirmar acceso MQTT en {ip}:{port}: {e}")
        return False, ""

    client.loop_start()
    accepted.wait(REQUEST_TIMEOUT)
    client.loop_stop()
    client.disconnect()

    if result["ok"]:
        return True, "CONNACK 0 (aceptado)"
    return False, ""


@actions.add_function(".initial_access", (str,))
def initial_access(target):
    """
    Confirma acceso inicial real usando las credenciales válidas encontradas
    por credAgR. Parámetro: IP de un target o "all".
    """
    print("[*] Iniciando verificación de acceso inicial...")

    try:
        with open("credentials.json", "r") as f:
            credenciales = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print("[!] No se encontró credentials.json válido. Ejecuta cred_scan primero.")
        return True

    if target.lower() != "all":
        credenciales = [c for c in credenciales if c.get("ip") == target]

    if not credenciales:
        print("[*] No hay credenciales válidas registradas, nada que verificar")
        return True

    accesos = []

    for cred in credenciales:
        ip = cred.get("ip")
        port = cred.get("port")
        protocol = cred.get("protocol")
        path = cred.get("path", "")
        user = cred.get("user")
        pwd = cred.get("password")

        print(f"[*] Verificando acceso {protocol}://{ip}:{port}{path} con {user}:{pwd}")

        if protocol == "ssh":
            ok, evidencia = _verify_ssh(ip, port, user, pwd)
        elif protocol in ("http", "https"):
            ok, evidencia = _verify_http(ip, port, protocol, path, user, pwd)
        elif protocol == "mqtt":
            ok, evidencia = _verify_mqtt(ip, port, user, pwd)
        else:
            print(f"[!] Protocolo no soportado para verificación: {protocol}")
            continue

        if ok:
            acceso = {
                "ip": ip, "port": port, "protocol": protocol, "path": path,
                "user": user, "password": pwd, "evidence": evidencia,
            }
            accesos.append(acceso)
            events.finding(
                AGENT,
                f"[{AGENT}] Acceso inicial confirmado: {user}:{pwd} en {protocol}://{ip}:{port}{path}",
                mitre=MITRE_VALID_ACCOUNTS,
                detection_hint=(
                    "Login exitoso desde un origen que minutos antes generó una ráfaga de intentos de "
                    "autenticación fallidos contra el mismo servicio — correlacionar ambos eventos por IP "
                    "de origen suele ser la señal más confiable, más que cualquiera de los dos por separado."
                ),
                **acceso,
            )
        else:
            print(f"[*] No se pudo confirmar acceso en {protocol}://{ip}:{port}")

    try:
        with open("access.json", "w") as f:
            json.dump(accesos, f, indent=2)
    except IOError as e:
        print(f"[!] Error guardando access.json: {e}")

    print(f"[+] Verificación de acceso inicial completada. Accesos confirmados: {len(accesos)}")
    return True
