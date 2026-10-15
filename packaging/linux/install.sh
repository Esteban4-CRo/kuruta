#!/usr/bin/env bash
# Script de instalación universal de Kuruta IDS para Linux
# Compatible con Ubuntu, Debian, Arch, Fedora, openSUSE y derivadas

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "Este script de instalación requiere privilegios de superusuario."
   echo "Ejecuta: sudo $0"
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BIN_PATH="${PROJECT_ROOT}/dist/release/kuruta-linux-x64"
LOGO_PATH="${PROJECT_ROOT}/assets/kuruta-logo.png"
DESKTOP_PATH="${SCRIPT_DIR}/kuruta.desktop"

if [[ ! -f "${BIN_PATH}" ]]; then
    # Revisar si se encuentra en la misma carpeta (empaquetado tar.gz)
    if [[ -f "${SCRIPT_DIR}/kuruta-linux-x64" ]]; then
        BIN_PATH="${SCRIPT_DIR}/kuruta-linux-x64"
        LOGO_PATH="${SCRIPT_DIR}/kuruta-logo.png"
    else
        echo "Error: No se encontró el binario kuruta-linux-x64."
        echo "Compila primero con: python scripts/build_release.py --platform linux"
        exit 1
    fi
fi

echo "============================================"
echo "    Instalando Kuruta IDS en el sistema     "
echo "============================================"

# 1. Copiar ejecutable
echo "-> Instalando binario en /usr/local/bin/kuruta..."
cp "${BIN_PATH}" /usr/local/bin/kuruta-linux-x64
chmod 755 /usr/local/bin/kuruta-linux-x64
ln -sf /usr/local/bin/kuruta-linux-x64 /usr/local/bin/kuruta

# 2. Configurar capacidades de captura de paquetes (sin necesidad de sudo)
echo "-> Otorgando capacidades raw de red (setcap)..."
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/kuruta-linux-x64 || {
        echo "Aviso: No se pudo ejecutar setcap. Se necesitará sudo para capturar en interfaces físicas."
    }
else
    echo "Aviso: 'setcap' no encontrado. Instala libcap2-bin en Debian/Ubuntu."
fi

# 3. Instalar icono oficial
echo "-> Instalando icono oficial..."
mkdir -p /usr/share/icons/hicolor/256x256/apps/
cp "${LOGO_PATH}" /usr/share/icons/hicolor/256x256/apps/kuruta.png

# 4. Instalar acceso directo en el menú de aplicaciones
echo "-> Instalando lanzador de escritorio..."
mkdir -p /usr/share/applications/
sed 's|Exec=kuruta-linux-x64|Exec=/usr/local/bin/kuruta|g' "${DESKTOP_PATH}" > /usr/share/applications/kuruta.desktop
chmod 644 /usr/share/applications/kuruta.desktop

# 5. Actualizar bases de datos del sistema
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications/ || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q /usr/share/icons/hicolor/ || true
fi

echo "============================================"
echo " ✓ Kuruta IDS instalado exitosamente!"
echo " ✓ Puedes abrirlo desde el menú de aplicaciones o escribiendo 'kuruta'"
echo "============================================"
