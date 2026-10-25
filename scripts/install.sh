#!/bin/sh
# Script d'installation rapide de Sentinel Net pour Linux et macOS.
# Usage : curl -fsSL https://raw.githubusercontent.com/abiyeenzo/sentinel-net/main/scripts/install.sh | sh

set -eu

REPO="${SENTINEL_NET_REPO:-abiyeenzo/sentinel-net}"
VERSION="${SENTINEL_NET_VERSION:-latest}"

uname_s="$(uname -s)"
case "$uname_s" in
  Linux*)  OS="linux" ;;
  Darwin*) OS="darwin" ;;
  *)
    echo "Erreur : systeme non supporte par ce script ($uname_s). Utilisez install.ps1 sous Windows." >&2
    exit 1
    ;;
esac

uname_m="$(uname -m)"
case "$uname_m" in
  x86_64|amd64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Erreur : architecture processeur non supportee ($uname_m)." >&2
    exit 1
    ;;
esac

ASSET="sentinel-net-${OS}-${ARCH}"
if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  case "$VERSION" in
    v*) TAG="$VERSION" ;;
    *)  TAG="v${VERSION}" ;;
  esac
  BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

fetch_file() {
  src="$1"
  dst="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$src" -o "$dst"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dst" "$src"
  else
    echo "Erreur : curl ou wget est requis pour le telechargement." >&2
    exit 1
  fi
}

echo "Telechargement de ${ASSET} depuis GitHub Releases..."
fetch_file "${BASE_URL}/${ASSET}" "${TMP_DIR}/${ASSET}"
fetch_file "${BASE_URL}/SHA256SUMS.txt" "${TMP_DIR}/SHA256SUMS.txt"

EXPECTED_HASH="$(awk -v target="$ASSET" '$2 == target || $2 == ("*" target) { print $1; exit }' "${TMP_DIR}/SHA256SUMS.txt")"
if [ -z "$EXPECTED_HASH" ]; then
  echo "Erreur : empreinte SHA-256 introuvable pour ${ASSET} dans SHA256SUMS.txt." >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_HASH="$(sha256sum "${TMP_DIR}/${ASSET}" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL_HASH="$(shasum -a 256 "${TMP_DIR}/${ASSET}" | awk '{ print $1 }')"
else
  ACTUAL_HASH="$EXPECTED_HASH"
  echo "Avertissement : ni sha256sum ni shasum n'est disponible, verification ignoree." >&2
fi

if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
  echo "Erreur : echec de verification SHA-256 (attendu=${EXPECTED_HASH}, recu=${ACTUAL_HASH})." >&2
  exit 1
fi

chmod +x "${TMP_DIR}/${ASSET}"

if [ -n "${INSTALL_DIR:-}" ]; then
  DEST_DIR="$INSTALL_DIR"
elif [ -w "/usr/local/bin" ]; then
  DEST_DIR="/usr/local/bin"
elif [ "$(id -u)" -eq 0 ]; then
  DEST_DIR="/usr/local/bin"
else
  DEST_DIR="${HOME}/.local/bin"
fi

mkdir -p "$DEST_DIR"
mv "${TMP_DIR}/${ASSET}" "${DEST_DIR}/sentinel-net"

if [ "$OS" = "darwin" ] && command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "${DEST_DIR}/sentinel-net" 2>/dev/null || true
fi

echo "Installation terminee : ${DEST_DIR}/sentinel-net"
"${DEST_DIR}/sentinel-net" --version || true

case ":${PATH}:" in
  *":${DEST_DIR}:"*) ;;
  *)
    echo "Note : ajoutez ${DEST_DIR} a votre PATH pour appeler 'sentinel-net' depuis n'importe quel dossier :"
    echo "  export PATH=\"${DEST_DIR}:\$PATH\""
    ;;
esac
