#!/usr/bin/env bash
set -euo pipefail

VERSION="$(grep '^version =' "${ROOT}/Cargo.toml" | head -1 | cut -d '"' -f 2)"
ARCH="amd64"
PACKAGE="cloudflare-ddns"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${ROOT}/build/package"
OUTPUT="${ROOT}/build/output"

echo "Building ${PACKAGE} ${VERSION}"

# Compile release binary.
cd "${ROOT}"
cargo build --release --locked

# Reset package staging area.
rm -rf "${STAGE}" "${OUTPUT}"
mkdir -p "${OUTPUT}"

install -d "${STAGE}/DEBIAN"
install -d "${STAGE}/usr/bin"
install -d "${STAGE}/usr/lib/systemd/system"
install -d "${STAGE}/etc/cloudflare-ddns"

# Install binary.
install -m 755 \
    target/release/cloudflare-ddns \
    "${STAGE}/usr/bin/cloudflare-ddns"

# Install systemd service.
install -m 644 \
    packaging/cloudflare-ddns.service \
    "${STAGE}/usr/lib/systemd/system/cloudflare-ddns.service"

# Install default configuration.
install -m 640 \
    config/config.toml \
    "${STAGE}/etc/cloudflare-ddns/config.toml"

# Create an empty credentials file.
cat > "${STAGE}/etc/cloudflare-ddns/cloudflare.env" <<'EOF'
CLOUDFLARE_API_TOKEN=
EOF

chmod 600 "${STAGE}/etc/cloudflare-ddns/cloudflare.env"

# Package metadata.
cat > "${STAGE}/DEBIAN/control" <<EOF
Package: ${PACKAGE}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libc6 (>= 2.35)
Maintainer: Your Name <you@example.com>
Description: Cloudflare Dynamic DNS updater
 Lightweight Rust-based Dynamic DNS client for Ubuntu.
EOF

# Mark configuration as persistent.
cat > "${STAGE}/DEBIAN/conffiles" <<'EOF'
/etc/cloudflare-ddns/config.toml
/etc/cloudflare-ddns/cloudflare.env
EOF

# Package installation script.
cat > "${STAGE}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if ! getent group cloudflare-ddns >/dev/null; then
    addgroup --system cloudflare-ddns
fi

if ! getent passwd cloudflare-ddns >/dev/null; then
    adduser --system \
        --ingroup cloudflare-ddns \
        --no-create-home \
        --home /nonexistent \
        --shell /usr/sbin/nologin \
        cloudflare-ddns
fi

chown root:cloudflare-ddns \
    /etc/cloudflare-ddns/config.toml \
    /etc/cloudflare-ddns/cloudflare.env

chmod 640 /etc/cloudflare-ddns/config.toml
chmod 640 /etc/cloudflare-ddns/cloudflare.env

systemctl daemon-reload || true

echo "Cloudflare DDNS installed."
echo "Configure /etc/cloudflare-ddns before enabling the service."

exit 0
EOF

chmod 755 "${STAGE}/DEBIAN/postinst"

# Package removal script.
cat > "${STAGE}/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

systemctl daemon-reload || true

exit 0
EOF

chmod 755 "${STAGE}/DEBIAN/postrm"

# Build Debian package.
dpkg-deb --build --root-owner-group \
    "${STAGE}" \
    "${OUTPUT}/${PACKAGE}_${VERSION}_${ARCH}.deb"

echo
echo "Package created:"
echo "${OUTPUT}/${PACKAGE}_${VERSION}_${ARCH}.deb"
