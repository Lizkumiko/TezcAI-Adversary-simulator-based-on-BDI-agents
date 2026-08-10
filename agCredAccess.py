#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Filename:  agCredAccess.py
# Version: 1.0.0
#
# Descripción: Acciones del agente BDI de acceso por credenciales (agCredAccess).
#              MITRE ATT&CK: TA0006 Credential Access.
#              No ejecuta pruebas de credenciales por sí mismo: delibera sobre
#              la fase y delega la ejecución en el agente reactivo credAgR.
#
# ================================================================================================

import events

AGENT = "agCredAccess"

actions = events.make_bdi_actions(AGENT)
