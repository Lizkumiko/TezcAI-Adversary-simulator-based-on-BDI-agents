#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Filename:  events.py
# Version: 1.0.0
#
# Descripción: Emisor central de eventos de la simulación. Cada evento se
#              imprime en consola (coloreado por agente) y se publica por
#              WebSocket como JSON. Los agentes BDI/reactivos no conocen esta
#              infraestructura: solo invocan acciones semánticas (.ev_*) y es
#              el código Python el que decide cómo transportar la señal.
#
# ================================================================================================

import threading
import uuid
from datetime import datetime, timezone

import agentspeak
import agentspeak.stdlib
from colorama import Fore, Style

import ws_server

_AGENT_COLORS = [Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.BLUE, Fore.GREEN, Fore.RED, Fore.WHITE]
_agent_colors = {}
_colors_lock = threading.Lock()
_session_id = str(uuid.uuid4())


def _color_for(agent):
    with _colors_lock:
        if agent not in _agent_colors:
            _agent_colors[agent] = _AGENT_COLORS[len(_agent_colors) % len(_AGENT_COLORS)]
        return _agent_colors[agent]


def jsonable(value):
    """Convierte valores provenientes de AgentSpeak (Literal, tuplas, etc.) en algo serializable a JSON."""
    if isinstance(value, agentspeak.Literal):
        if not value.args:
            return value.functor
        return {"functor": value.functor, "args": [jsonable(a) for a in value.args]}
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


def emit(event_type, agent, agent_kind, message, mitre=None, detection_hint=None, **data):
    """Construye el evento, lo imprime en consola y lo publica por WebSocket."""
    event = {
        "id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": _session_id,
        "type": event_type,
        "agent": agent,
        "agent_kind": agent_kind,
        "mitre": mitre,
        "detection_hint": detection_hint,
        "data": {k: jsonable(v) for k, v in data.items()},
        "message": message,
    }

    color = _color_for(agent)
    print(f"{color}{message}{Style.RESET_ALL}")

    ws_server.publish(event)
    return event


def finding(agent, message, mitre=None, detection_hint=None, **data):
    """Emite un hallazgo (credenciales, accesos, vulnerabilidades...) descubierto
    por un agente reactivo mientras ejecuta una acción. Se distingue de 'log'
    porque es el tipo de evento que le importa a un panel de hallazgos en la UI.
    detection_hint describe el patrón de log/tráfico que este hallazgo debería
    producir del lado defensor (SIEM/WAF/IDS) — TezcAI no detecta nada, solo
    genera el tráfico; el hint es la referencia para validar si el SOC lo cachó."""
    return emit("finding", agent, "reactive", message, mitre=mitre, detection_hint=detection_hint, **data)


def make_bdi_actions(agent_name, parent=None):
    """Crea un juego de acciones .ev_* (reporte de fase/objetivo/delegación/
    belief) ya ligadas al nombre de un agente BDI concreto. Cada agente BDI
    debe construir el suyo con su propio nombre; así el evento emitido siempre
    identifica correctamente a quién lo generó, sin código duplicado por agente."""
    actions = agentspeak.Actions(parent if parent is not None else agentspeak.stdlib.actions)

    @actions.add_procedure(".ev_phase", (None,))
    def ev_phase(phase):
        emit("phase", agent_name, "bdi", f"[{agent_name}] Fase: {phase}", phase=phase)

    @actions.add_procedure(".ev_goal_start", (None,))
    def ev_goal_start(goal):
        emit("goal_start", agent_name, "bdi", f"[{agent_name}] Objetivo iniciado: !{goal}", goal=goal)

    @actions.add_procedure(".ev_goal_end", (None, None))
    def ev_goal_end(goal, success):
        emit(
            "goal_end", agent_name, "bdi",
            f"[{agent_name}] Objetivo finalizado: !{goal} (éxito={success})",
            goal=goal, success=success,
        )

    @actions.add_procedure(".ev_delegation", (None, None))
    def ev_delegation(to, action):
        emit(
            "delegation", agent_name, "bdi",
            f"[{agent_name}] Le pido al agente reactivo simple {to} que inicie {action}",
            to=to, action=action,
        )

    @actions.add_procedure(".ev_handoff", (None, None))
    def ev_handoff(to, goal):
        emit(
            "handoff", agent_name, "bdi",
            f"[{agent_name}] Entrega la fase al agente BDI {to} (objetivo !{goal})",
            to=to, goal=goal,
        )

    @actions.add_procedure(".ev_belief", (None, None, None))
    def ev_belief(name, value, source):
        emit(
            "belief", agent_name, "bdi",
            f"[{agent_name}] Belief: {name}({value}) de {source}",
            name=name, value=value, source=source,
        )

    @actions.add_procedure(".ev_log", (None,))
    def ev_log(message):
        emit("log", agent_name, "bdi", f"[{agent_name}] {message}")

    return actions


def make_reactive_actions(agent_name, parent=None):
    """Crea un juego de acciones .ev_* (reporte de inicio/resultado de acción)
    ya ligadas al nombre de un agente reactivo simple concreto. El agente
    reactivo no delibera: solo ejecuta lo que un BDI le pide y reporta qué hizo."""
    actions = agentspeak.Actions(parent if parent is not None else agentspeak.stdlib.actions)

    @actions.add_procedure(".ev_action_start", (None, None, None))
    def ev_action_start(action, requested_by, detail):
        detalle_txt = f": {detail}" if detail else ""
        emit(
            "action_start", agent_name, "reactive",
            f"[{agent_name}] {requested_by} me pide ejecutar {action}{detalle_txt}",
            action=action, requested_by=requested_by, detail=detail,
        )

    @actions.add_procedure(".ev_action_result", (None, None, None))
    def ev_action_result(action, success, detail):
        detalle_txt = f" — {detail}" if detail else ""
        emit(
            "action_result", agent_name, "reactive",
            f"[{agent_name}] {action} completado. Éxito: {success}{detalle_txt}",
            action=action, success=success, detail=detail,
        )

    @actions.add_procedure(".ev_log", (None,))
    def ev_log(message):
        emit("log", agent_name, "reactive", f"[{agent_name}] {message}")

    return actions
