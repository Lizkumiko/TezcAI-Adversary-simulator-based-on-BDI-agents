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

import events
import ws_server

# Agentes reactivos simples: ejecutan lo que un BDI les pide, no deliberan.
import networkAgR
import credAgR
import initAgR

# Agentes BDI: deliberan sobre metas y delegan en los reactivos.
import agCredAccess
import agInitialAccess

# Inicializar colorama para colores en terminal
init(autoreset=True)

# Acciones del agente coordinador (agDiscovery). Es el único agente BDI cuyas
# acciones viven en el entry point en vez de en su propio módulo, por ser
# también el punto de arranque histórico del proyecto.
actions = events.make_bdi_actions("agDiscovery")


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


# Agentes a cargar en el entorno: (archivo .asl, acciones del agente).
# Reactivos primero (no dependen de nadie), BDI después (delegan en ellos).
AGENTS_TO_LOAD = [
    ("networkAgR.asl", networkAgR.actions),
    ("credAgR.asl", credAgR.actions),
    ("initAgR.asl", initAgR.actions),
    ("agDiscovery.asl", actions),
    ("agCredAccess.asl", agCredAccess.actions),
    ("agInitialAccess.asl", agInitialAccess.actions),
]


def main():
    """Función principal que inicializa y ejecuta los agentes BDI"""

    # Mostrar logo o banner
    if not load_logo():
        print_banner()

    ws_server.start()
    print(Fore.CYAN + "[*] Servidor WebSocket escuchando en ws://0.0.0.0:8765" + Style.RESET_ALL)

    print(Fore.CYAN + "[*] Inicializando entorno de agentes BDI..." + Style.RESET_ALL)

    # Crear entorno de ejecución
    env = agentspeak.runtime.Environment()
    base_dir = os.path.dirname(__file__)

    agents = []
    for filename, agent_actions in AGENTS_TO_LOAD:
        agent_path = os.path.join(base_dir, filename)
        try:
            with open(agent_path) as source:
                agents.append(env.build_agent(source, agent_actions))
            print(Fore.GREEN + f"[+] Agente cargado: {filename}" + Style.RESET_ALL)
        except FileNotFoundError:
            print(Fore.RED + f"[!] Error: No se encontró {agent_path}" + Style.RESET_ALL)
            return
        except Exception as e:
            print(Fore.RED + f"[!] Error cargando {filename}: {e}" + Style.RESET_ALL)
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
