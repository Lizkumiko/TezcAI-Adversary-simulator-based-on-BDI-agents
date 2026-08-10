#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Filename:  agInitialAccess.py
# Version: 1.0.0
#
# Descripción: Acciones del agente BDI de acceso inicial (agInitialAccess).
#              MITRE ATT&CK: TA0001 Initial Access.
#              No verifica accesos por sí mismo: delibera sobre la fase y
#              delega la ejecución en el agente reactivo initAgR.
#
# ================================================================================================

import events

AGENT = "agInitialAccess"

actions = events.make_bdi_actions(AGENT)
