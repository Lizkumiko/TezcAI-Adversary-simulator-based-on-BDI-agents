#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Filename:  ws_server.py
# Version: 1.0.0
#
# Descripción: Servidor WebSocket que retransmite los eventos de la simulación
#              a los clientes conectados (frontend). Corre en un hilo propio
#              con su loop de asyncio para no bloquear el motor síncrono de
#              agentspeak.
#
# ================================================================================================

import asyncio
import json
import threading

import websockets

_loop = None
_queue = None
_clients = set()
_ready = threading.Event()


async def _handler(websocket):
    _clients.add(websocket)
    try:
        async for _ in websocket:
            pass  # canal de solo lectura para el frontend
    finally:
        _clients.discard(websocket)


async def _broadcaster():
    while True:
        event = await _queue.get()
        if _clients:
            payload = json.dumps(event, ensure_ascii=False)
            await asyncio.gather(
                *(client.send(payload) for client in list(_clients)),
                return_exceptions=True,
            )


async def _main(host, port):
    global _queue
    _queue = asyncio.Queue()
    _ready.set()
    async with websockets.serve(_handler, host, port):
        await _broadcaster()


def start(host="0.0.0.0", port=8765):
    """Arranca el servidor WebSocket en un hilo de fondo. Idempotente."""
    global _loop
    if _loop is not None:
        return

    _loop = asyncio.new_event_loop()

    def _runner():
        asyncio.set_event_loop(_loop)
        _loop.run_until_complete(_main(host, port))

    threading.Thread(target=_runner, daemon=True).start()
    _ready.wait()


def publish(event: dict):
    """Encola un evento para difusión. Seguro de llamar desde cualquier hilo."""
    if _loop is None or _queue is None:
        return
    _loop.call_soon_threadsafe(_queue.put_nowait, event)
