#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Filename:  agDiscover.py
# Version: 2.0.0
#
# Descripción: Punto de entrada principal para el simulador TezcAI.
#              Inicializa el entorno de agentes BDI y coordina la ejecución.
#
# ================================================================================================

import os
import agentspeak
import agentspeak.runtime
import agentspeak.stdlib
from colorama import init, Fore, Style

# Importar acciones del agente de red
import networkAgR

# Inicializar colorama para colores en terminal
init(autoreset=True)

# Acciones del agente coordinador (discovery)
actions = agentspeak.Actions(agentspeak.stdlib.actions)


@actions.add_procedure(".creaArch", (str,))
def crea_archivo(texto):
    """Crea un archivo con el texto especificado"""
    try:
        with open("archivo.txt", "w") as f:
            f.write(texto)
        print(f"[+] Archivo creado con contenido: {texto[:50]}...")
    except IOError as e:
        print(f"[!] Error creando archivo: {e}")


@actions.add_procedure(".print_banner", tuple())
def print_banner():
    """Muestra el banner del programa"""
    banner = """
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║   ████████╗███████╗███████╗ ██████╗ █████╗ ██╗                ║
    ║   ╚══██╔══╝██╔════╝╚══███╔╝██╔════╝██╔══██╗██║                ║
    ║      ██║   █████╗    ███╔╝ ██║     ███████║██║                ║
    ║      ██║   ██╔══╝   ███╔╝  ██║     ██╔══██║██║                ║
    ║      ██║   ███████╗███████╗╚██████╗██║  ██║██║                ║
    ║      ╚═╝   ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝                ║
    ║                                                                ║
    ║   Adversary Simulator based on BDI Agents                      ║
    ║   Version 2.0.0                                                ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
    """
    print(Fore.GREEN + banner + Style.RESET_ALL)


def load_logo():
    """Carga y muestra el logo desde archivo si existe"""
    logo_path = os.path.join(os.path.dirname(__file__), "logo.dat")
    if os.path.exists(logo_path):
        try:
            with open(logo_path, "r") as logo_file:
                content = logo_file.read()
                print(Fore.GREEN + content + Style.RESET_ALL)
                return True
        except IOError:
            pass
    return False


def main():
    """Función principal que inicializa y ejecuta los agentes BDI"""

    # Mostrar logo o banner
    if not load_logo():
        print_banner()

    print(Fore.CYAN + "[*] Inicializando entorno de agentes BDI..." + Style.RESET_ALL)

    # Crear entorno de ejecución
    env = agentspeak.runtime.Environment()

    # Cargar agente de red (networkAgR) con sus acciones
    network_agent_path = os.path.join(os.path.dirname(__file__), "networkAgR.asl")
    try:
        with open(network_agent_path) as source:
            agents = env.build_agents(source, 1, networkAgR.actions)
        print(Fore.GREEN + "[+] Agente de red (networkAgR) cargado" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + f"[!] Error: No se encontró {network_agent_path}" + Style.RESET_ALL)
        return
    except Exception as e:
        print(Fore.RED + f"[!] Error cargando agente de red: {e}" + Style.RESET_ALL)
        return

    # Cargar agente de descubrimiento (agDiscovery) con sus acciones
    discovery_agent_path = os.path.join(os.path.dirname(__file__), "agDiscovery.asl")
    try:
        with open(discovery_agent_path) as source:
            agents.append(env.build_agent(source, actions))
        print(Fore.GREEN + "[+] Agente de descubrimiento (agDiscovery) cargado" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + f"[!] Error: No se encontró {discovery_agent_path}" + Style.RESET_ALL)
        return
    except Exception as e:
        print(Fore.RED + f"[!] Error cargando agente de descubrimiento: {e}" + Style.RESET_ALL)
        return

    print(Fore.CYAN + "[*] Ejecutando simulación..." + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)

    # Ejecutar el entorno de agentes
    try:
        env.run()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Simulación interrumpida por el usuario" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Error durante la ejecución: {e}" + Style.RESET_ALL)

    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Simulación finalizada" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
