#!/usr/bin/env bash
#
# setup.sh - Prepara el entorno para correr TezcAI sin Docker.
#
# Qué hace:
#   1. Verifica Python 3.9+.
#   2. Crea (o reutiliza) el virtualenv en ./venv.
#   3. Instala requirements.txt dentro del venv.
#   4. Verifica que exista el binario 'nmap' (networkAgR lo invoca vía
#      python-nmap, que solo es un wrapper: el binario debe estar instalado
#      en el sistema aparte).
#   5. Avisa si no se está corriendo como root, ya que la detección de OS
#      (-O de nmap) y algunas pruebas de red requieren privilegios elevados.
#
# TezcAI escanea la red real del host donde corre, así que este script
# instala nativo (sin contenedores): un contenedor con networking en modo
# bridge detectaría la subred interna de Docker, no la LAN real a evaluar.
#
# Uso:
#   ./setup.sh
#   source venv/bin/activate && sudo -E python agDiscover.py
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[!]${NC} $1"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------------------------
# 1. Python 3.9+
# ---------------------------------------------------------------------------
info "Verificando Python 3..."

PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        PYTHON_BIN="$candidate"
        break
    fi
done

[ -n "$PYTHON_BIN" ] || fail "No se encontró Python 3. Instálalo antes de continuar."

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_OK="$("$PYTHON_BIN" -c 'import sys; print(1 if sys.version_info >= (3, 9) else 0)')"
[ "$PY_OK" = "1" ] || fail "Se requiere Python 3.9+, se encontró $PY_VERSION."
ok "Python $PY_VERSION encontrado ($PYTHON_BIN)"

# ---------------------------------------------------------------------------
# 2. Virtualenv
# ---------------------------------------------------------------------------
if [ -d "venv" ]; then
    info "Ya existe ./venv, se reutiliza"
else
    info "Creando virtualenv en ./venv..."
    "$PYTHON_BIN" -m venv venv || fail "No se pudo crear el virtualenv."
    ok "Virtualenv creado"
fi

# shellcheck disable=SC1091
source venv/bin/activate

# ---------------------------------------------------------------------------
# 3. Dependencias de Python
# ---------------------------------------------------------------------------
info "Instalando dependencias de requirements.txt..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt || fail "Falló la instalación de dependencias."
ok "Dependencias de Python instaladas"

# ---------------------------------------------------------------------------
# 4. Binario de nmap
# ---------------------------------------------------------------------------
info "Verificando binario 'nmap'..."
if command -v nmap >/dev/null 2>&1; then
    ok "nmap encontrado ($(command -v nmap))"
else
    warn "No se encontró el binario 'nmap' en el PATH."
    if command -v apt-get >/dev/null 2>&1; then
        warn "Instálalo con: sudo apt-get install -y nmap"
    elif command -v dnf >/dev/null 2>&1; then
        warn "Instálalo con: sudo dnf install -y nmap"
    elif command -v pacman >/dev/null 2>&1; then
        warn "Instálalo con: sudo pacman -S nmap"
    elif command -v brew >/dev/null 2>&1; then
        warn "Instálalo con: brew install nmap"
    else
        warn "Instálalo con el gestor de paquetes de tu sistema."
    fi
fi

# ---------------------------------------------------------------------------
# 5. Privilegios
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    warn "No estás corriendo como root. La detección de OS (nmap -O) y algunas"
    warn "pruebas de red fallarán o darán resultados incompletos sin privilegios"
    warn "elevados. Corre la simulación con: sudo -E python agDiscover.py"
else
    ok "Corriendo con privilegios de root"
fi

echo ""
ok "Setup completo. Para correr TezcAI:"
echo "    source venv/bin/activate"
echo "    sudo -E python agDiscover.py"
echo ""
ok "Para ver el panel en vivo, abre web/index.html en el navegador."
