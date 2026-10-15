#!/usr/bin/env bash
set -euo pipefail

# Build a Debian/Ubuntu .deb package for Kuruta IDS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist/release"
PKG_DIR="${ROOT_DIR}/dist/deb-staging"
BIN_SRC="${DIST_DIR}/kuruta-linux-x64"
LOGO_SRC="${ROOT_DIR}/assets/kuruta-logo.png"

if [[ ! -f "${BIN_SRC}" ]]; then
    echo "Error: ${BIN_SRC} does not exist. Run scripts/build_release.py --platform linux first."
    exit 1
fi

rm -rf "${PKG_DIR}"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/256x256/apps"
mkdir -p "${PKG_DIR}/usr/share/doc/kuruta"

# Copy binary, desktop entry, icon and docs
cp "${BIN_SRC}" "${PKG_DIR}/usr/bin/kuruta-linux-x64"
chmod 755 "${PKG_DIR}/usr/bin/kuruta-linux-x64"

cp "${SCRIPT_DIR}/kuruta.desktop" "${PKG_DIR}/usr/share/applications/kuruta.desktop"
cp "${LOGO_SRC}" "${PKG_DIR}/usr/share/icons/hicolor/256x256/apps/kuruta.png"
cp "${ROOT_DIR}/README.md" "${PKG_DIR}/usr/share/doc/kuruta/README"
cp "${ROOT_DIR}/LICENSE" "${PKG_DIR}/usr/share/doc/kuruta/copyright"

# Create symlink /usr/bin/kuruta -> kuruta-linux-x64
ln -sf "kuruta-linux-x64" "${PKG_DIR}/usr/bin/kuruta"

# Create Debian control file
cat <<EOF > "${PKG_DIR}/DEBIAN/control"
Package: kuruta
Version: 0.2.0
Section: net
Priority: optional
Architecture: amd64
Depends: libc6, libpcap0.8
Maintainer: Esteban4-CRo <juancampinoc@gmail.com>
Description: Local IDS and packet sniffer
 Kuruta captures network frames on local interfaces, dissectors them
 like Wireshark, detects network anomalies, and presents a sleek
 black-and-white desktop UI.
EOF

# Create postinst to setcap cap_net_raw
cat <<'EOF' > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip /usr/bin/kuruta-linux-x64 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q || true
fi
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

dpkg-deb --build --root-owner-group "${PKG_DIR}" "${DIST_DIR}/kuruta-linux-x64.deb"
echo "Created Debian package: ${DIST_DIR}/kuruta-linux-x64.deb"
