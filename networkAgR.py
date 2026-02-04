# -*- coding: UTF-8 -*-
#!/usr/bin/python
#
# Filename:  networkAgR.py
# Version: 2.0.0
#
# ================================================================================================
#
# Descripción:   Acciones del agente reactivo de red "networkAgR"
#
# whoami:           Determina la ubicación del agente en la red (IP, máscara, gateway)
# network_scanning: Descubre activos alcanzables en el segmento de red
# service_scanning: Escanea puertos y servicios en activos descubiertos
# os_detection:     Detecta sistema operativo de los activos
#
# ================================================================================================

import agentspeak
import agentspeak.stdlib
import nmap
import platform
import socket
import json
from netifaces import interfaces, ifaddresses, AF_INET, AF_LINK
from ipaddress import IPv4Network, IPv4Interface

actions = agentspeak.Actions(agentspeak.stdlib.actions)
SISTEMA = platform.system()


class NetworkLocation:
    """Clase para almacenar información de ubicación en la red"""
    def __init__(self):
        self.ip = None
        self.netmask = None
        self.network = None
        self.interface = None
        self.mac = None
        self.gateway = None

    def to_dict(self):
        return {
            "ip": self.ip,
            "netmask": self.netmask,
            "network": str(self.network) if self.network else None,
            "interface": self.interface,
            "mac": self.mac,
            "gateway": self.gateway
        }


def get_default_gateway():
    """Obtiene el gateway por defecto del sistema"""
    try:
        if SISTEMA == "Linux":
            with open("/proc/net/route") as f:
                for line in f:
                    fields = line.strip().split()
                    if fields[1] == '00000000':  # Default route
                        gateway = socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])
                        return gateway
        elif SISTEMA == "Windows":
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if 'Default Gateway' in line or 'Puerta de enlace' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gateway = parts[1].strip()
                        if gateway:
                            return gateway
    except Exception as e:
        print(f"[!] Error obteniendo gateway: {e}")
    return None


def get_active_interface():
    """
    Detecta la interfaz de red activa (la que tiene conectividad).
    Filtra interfaces loopback y virtuales.
    """
    location = NetworkLocation()

    # Interfaces a ignorar
    ignore_interfaces = ['lo', 'lo0', 'docker0', 'br-', 'veth', 'virbr']

    try:
        # Método 1: Detectar interfaz activa mediante conexión UDP
        # (no envía datos, solo determina qué interfaz usaría)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.connect(('8.8.8.8', 80))
            active_ip = s.getsockname()[0]
            s.close()
        except Exception:
            active_ip = None
            s.close()

        # Buscar la interfaz que tiene esa IP
        for iface_name in interfaces():
            # Ignorar interfaces virtuales/loopback
            if any(ignore in iface_name for ignore in ignore_interfaces):
                continue

            addrs = ifaddresses(iface_name)

            # Obtener direcciones IPv4
            if AF_INET in addrs:
                for addr in addrs[AF_INET]:
                    ip = addr.get('addr')
                    netmask = addr.get('netmask')

                    # Ignorar loopback
                    if ip and ip.startswith('127.'):
                        continue

                    # Si encontramos la IP activa, o si no teníamos IP activa y esta es válida
                    if ip and (ip == active_ip or (active_ip is None and not ip.startswith('169.254'))):
                        location.ip = ip
                        location.netmask = netmask
                        location.interface = iface_name

                        # Calcular red
                        if netmask:
                            try:
                                iface = IPv4Interface(f"{ip}/{netmask}")
                                location.network = iface.network
                            except Exception:
                                pass

                        # Obtener MAC
                        if AF_LINK in addrs:
                            for link_addr in addrs[AF_LINK]:
                                mac = link_addr.get('addr')
                                if mac and mac != '00:00:00:00:00:00':
                                    location.mac = mac
                                    break

                        # Si encontramos la IP activa, terminamos
                        if ip == active_ip:
                            location.gateway = get_default_gateway()
                            return location

        # Si no encontramos exactamente la activa pero tenemos una válida
        if location.ip:
            location.gateway = get_default_gateway()
            return location

    except Exception as e:
        print(f"[!] Error detectando interfaz activa: {e}")

    return location


@actions.add_function(".whoami", (str,))
def whoami(mensaje):
    """
    Determina la ubicación del agente en la red.
    Retorna la IP de la interfaz activa y guarda información detallada.
    """
    print(f"[*] {mensaje}")
    print("[*] Identificando ubicación en la red...")

    location = get_active_interface()

    if location.ip:
        print(f"[+] Interfaz activa: {location.interface}")
        print(f"[+] IP Local: {location.ip}")
        print(f"[+] Máscara: {location.netmask}")
        print(f"[+] Red: {location.network}")
        print(f"[+] MAC: {location.mac}")
        print(f"[+] Gateway: {location.gateway}")

        # Guardar resultados detallados
        try:
            with open("resultados.txt", "w") as f:
                f.write(f"IP:{location.ip}\n")
                f.write(f"Netmask:{location.netmask}\n")
                f.write(f"Network:{location.network}\n")
                f.write(f"Interface:{location.interface}\n")
                f.write(f"MAC:{location.mac}\n")
                f.write(f"Gateway:{location.gateway}\n")

            with open("network_info.json", "w") as f:
                json.dump(location.to_dict(), f, indent=2)

        except IOError as e:
            print(f"[!] Error guardando resultados: {e}")

        return location.ip
    else:
        print("[!] No se pudo determinar la ubicación en la red")
        return "unknown"


@actions.add_function(".network_scanning", (str,))
def network_scanning(direccion):
    """
    Escanea la red en busca de hosts activos.
    Parámetro: dirección IP (se agregará /24 automáticamente si no tiene CIDR)
    """
    print("[*] Iniciando descubrimiento de red...")

    try:
        scanner = nmap.PortScanner()

        # Agregar /24 si no tiene notación CIDR
        if '/' not in direccion:
            # Obtener los primeros 3 octetos para escanear la subred
            octetos = direccion.split('.')
            if len(octetos) >= 3:
                direccion = f"{octetos[0]}.{octetos[1]}.{octetos[2]}.0/24"
            else:
                direccion = f"{direccion}/24"

        print(f"[*] Escaneando: {direccion}")

        # Ping sweep para descubrir hosts
        scanner.scan(hosts=direccion, arguments='-sn -T4')

        hosts_activos = []
        for host in scanner.all_hosts():
            estado = scanner[host]['status']['state']
            if estado == 'up':
                host_info = {
                    "ip": host,
                    "status": estado,
                    "hostname": scanner[host].hostname() if scanner[host].hostname() else None
                }
                hosts_activos.append(host_info)
                print(f"[+] Host descubierto: {host} ({estado})")

        # Guardar targets para siguientes fases
        with open('targets.json', 'w') as f:
            json.dump(hosts_activos, f, indent=2)

        print(f"[+] Total hosts descubiertos: {len(hosts_activos)}")
        return True

    except nmap.PortScannerError as e:
        print(f"[!] Error de Nmap: {e}")
        print("[!] Asegúrate de que Nmap está instalado y tienes permisos")
        return False
    except Exception as e:
        print(f"[!] Error en escaneo de red: {e}")
        return False


@actions.add_function(".service_scanning", (str,))
def service_scanning(target):
    """
    Escanea puertos y servicios en un host específico o en todos los targets.
    Parámetro: IP del target o "all" para escanear todos los targets descubiertos
    """
    print("[*] Iniciando escaneo de servicios...")

    try:
        scanner = nmap.PortScanner()
        targets_to_scan = []

        # Determinar qué escanear
        if target.lower() == "all":
            try:
                with open('targets.json', 'r') as f:
                    targets_data = json.load(f)
                    targets_to_scan = [t['ip'] for t in targets_data if isinstance(t, dict)]
            except (FileNotFoundError, json.JSONDecodeError):
                print("[!] No se encontró archivo targets.json válido")
                return False
        else:
            targets_to_scan = [target]

        resultados = []

        for ip in targets_to_scan:
            print(f"[*] Escaneando servicios en: {ip}")

            try:
                # Escaneo de puertos comunes con detección de versiones
                scanner.scan(hosts=ip, arguments='-sV -sC -T4 --top-ports 1000')

                if ip in scanner.all_hosts():
                    host_result = {
                        "ip": ip,
                        "hostname": scanner[ip].hostname(),
                        "state": scanner[ip].state(),
                        "protocols": {}
                    }

                    for proto in scanner[ip].all_protocols():
                        ports_info = []
                        ports = scanner[ip][proto].keys()

                        for port in sorted(ports):
                            port_data = scanner[ip][proto][port]
                            port_info = {
                                "port": port,
                                "state": port_data['state'],
                                "service": port_data['name'],
                                "version": port_data.get('version', ''),
                                "product": port_data.get('product', ''),
                                "extrainfo": port_data.get('extrainfo', '')
                            }
                            ports_info.append(port_info)

                            if port_data['state'] == 'open':
                                version_str = f"{port_data.get('product', '')} {port_data.get('version', '')}".strip()
                                print(f"    [+] {port}/{proto} - {port_data['name']} {version_str}")

                        host_result["protocols"][proto] = ports_info

                    resultados.append(host_result)

            except Exception as e:
                print(f"[!] Error escaneando {ip}: {e}")
                continue

        # Guardar resultados
        with open('services.json', 'w') as f:
            json.dump(resultados, f, indent=2)

        print(f"[+] Escaneo de servicios completado. Resultados en services.json")
        return True

    except Exception as e:
        print(f"[!] Error en escaneo de servicios: {e}")
        return False


@actions.add_function(".os_detection", (bool,))
def os_detection(proceder):
    """
    Detecta el sistema operativo de los targets descubiertos.
    Requiere privilegios de root/admin para funcionar correctamente.
    """
    if not proceder:
        print("[!] Detección de OS cancelada")
        return False

    print("[*] Iniciando detección de sistemas operativos...")
    print("[!] Nota: Requiere privilegios de root/administrador")

    try:
        # Cargar targets
        try:
            with open('targets.json', 'r') as f:
                targets_data = json.load(f)
        except FileNotFoundError:
            print("[!] No se encontró targets.json. Ejecuta network_scanning primero.")
            return False
        except json.JSONDecodeError:
            print("[!] Error leyendo targets.json")
            return False

        scanner = nmap.PortScanner()
        resultados = []

        for target in targets_data:
            ip = target['ip'] if isinstance(target, dict) else target
            print(f"[*] Detectando OS en: {ip}")

            try:
                # Detección de OS con Nmap
                scanner.scan(hosts=ip, arguments='-O -T4')

                if ip in scanner.all_hosts():
                    os_info = {
                        "ip": ip,
                        "os_matches": [],
                        "os_fingerprint": None
                    }

                    # Obtener matches de OS
                    if 'osmatch' in scanner[ip]:
                        for osmatch in scanner[ip]['osmatch']:
                            match_info = {
                                "name": osmatch.get('name', 'Unknown'),
                                "accuracy": osmatch.get('accuracy', '0'),
                                "os_class": []
                            }

                            if 'osclass' in osmatch:
                                for osclass in osmatch['osclass']:
                                    match_info['os_class'].append({
                                        "type": osclass.get('type', ''),
                                        "vendor": osclass.get('vendor', ''),
                                        "osfamily": osclass.get('osfamily', ''),
                                        "osgen": osclass.get('osgen', '')
                                    })

                            os_info['os_matches'].append(match_info)

                            # Mostrar el mejor match
                            if len(os_info['os_matches']) == 1:
                                print(f"    [+] OS probable: {match_info['name']} ({match_info['accuracy']}%)")

                    # Fingerprint si está disponible
                    if 'fingerprint' in scanner[ip]:
                        os_info['os_fingerprint'] = scanner[ip]['fingerprint']

                    resultados.append(os_info)

            except Exception as e:
                print(f"[!] Error detectando OS en {ip}: {e}")
                continue

        # Guardar resultados
        with open('results.json', 'w') as f:
            json.dump(resultados, f, indent=2)

        print(f"[+] Detección de OS completada. Resultados en results.json")
        return True

    except Exception as e:
        print(f"[!] Error en detección de OS: {e}")
        return False
