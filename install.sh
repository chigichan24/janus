#!/bin/bash
# install.sh - Installer for janus binary
#
# Usage:
#   curl -sSfL https://raw.githubusercontent.com/chigichan24/janus/main/install.sh | bash
#
# Environment variables:
#   JANUS_VERSION      - Specific version to install (default: latest release)
#   JANUS_INSTALL_DIR  - Custom installation directory

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────

REPO="chigichan24/janus"
BINARY_NAME="janus"

# ── Utility functions ────────────────────────────────────────────────────────

info() {
  printf '[info] %s\n' "$*" >&2
}

error() {
  printf '[error] %s\n' "$*" >&2
  exit 1
}

# ── Detection functions ──────────────────────────────────────────────────────

# Detect the operating system and return the Rust target OS triple component.
detect_os() {
  local os
  os=$(uname -s)
  case "${os}" in
    Linux)  echo "unknown-linux-gnu" ;;
    Darwin) echo "apple-darwin" ;;
    *)      error "Unsupported operating system: ${os}" ;;
  esac
}

# Detect the CPU architecture and return the Rust target arch component.
detect_arch() {
  local arch
  arch=$(uname -m)
  case "${arch}" in
    x86_64)          echo "x86_64" ;;
    aarch64 | arm64) echo "aarch64" ;;
    *)               error "Unsupported architecture: ${arch}" ;;
  esac
}

# Determine where to install the binary and create the directory if needed.
# Priority: $JANUS_INSTALL_DIR > /usr/local/bin (if writable) > ~/.local/bin
ensure_install_dir() {
  if [ -n "${JANUS_INSTALL_DIR:-}" ]; then
    case "${JANUS_INSTALL_DIR}" in
      /*) ;;
      *)  error "JANUS_INSTALL_DIR must be an absolute path: ${JANUS_INSTALL_DIR}" ;;
    esac
    mkdir -p "${JANUS_INSTALL_DIR}"
    echo "${JANUS_INSTALL_DIR}"
    return
  fi

  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    echo "/usr/local/bin"
    return
  fi

  local dir="${HOME}/.local/bin"
  mkdir -p "${dir}"
  echo "${dir}"
}

# Fetch the latest release tag from the GitHub API.
# Uses sed/grep to parse JSON without requiring jq.
get_latest_version() {
  local url="https://api.github.com/repos/${REPO}/releases/latest"
  local version
  version=$(curl -sSfL "${url}" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
  if [ -z "${version}" ]; then
    error "Failed to determine latest version. Check network connectivity or set JANUS_VERSION manually."
  fi
  echo "${version}"
}

# Verify SHA256 checksum of a downloaded file against a checksums file.
verify_checksum() {
  local file="$1"
  local checksums="$2"
  local filename
  filename=$(basename "${file}")

  local expected
  expected=$(awk -v file="${filename}" '$2 == file || $2 == ("*" file) {print $1; exit}' "${checksums}")

  if [ -z "${expected}" ]; then
    error "No checksum found for ${filename}"
  fi

  local actual
  if command -v sha256sum > /dev/null 2>&1; then
    actual=$(sha256sum "${file}" | awk '{print $1}')
  elif command -v shasum > /dev/null 2>&1; then
    actual=$(shasum -a 256 "${file}" | awk '{print $1}')
  else
    error "No SHA256 tool found (need sha256sum or shasum)"
  fi

  if [ "${actual}" != "${expected}" ]; then
    error "Checksum verification failed for ${filename}"
  fi

  info "Checksum verified."
}

# Print post-install hints (macOS codesign, PATH warning, shell completions).
post_install_hints() {
  if [ "${OS}" = "apple-darwin" ] && [ -f "${INSTALL_DIR}/janus-entitlements.plist" ]; then
    info ""
    info "To enable Touch ID for group keys, run:"
    info "  codesign -s - --entitlements ${INSTALL_DIR}/janus-entitlements.plist \$(which ${BINARY_NAME})"
  fi

  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      info ""
      info "WARNING: ${INSTALL_DIR} is not in your PATH."
      info "Add it with: export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac

  if "${INSTALL_DIR}/${BINARY_NAME}" completions bash > /dev/null 2>&1; then
    info ""
    info "To enable shell completions, add to your shell config:"
    info "  eval \"\$(janus completions bash)\"    # Bash"
    info "  eval \"\$(janus completions zsh)\"     # Zsh"
    info "  janus completions fish | source     # Fish"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

OS=$(detect_os)
ARCH=$(detect_arch)
TARGET="${ARCH}-${OS}"
VERSION="${JANUS_VERSION:-$(get_latest_version)}"
ARCHIVE="${BINARY_NAME}-${VERSION}-${TARGET}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.sha256"
INSTALL_DIR=$(ensure_install_dir)

# Create a temporary directory and ensure it is cleaned up on exit.
JANUS_TMPDIR=$(mktemp -d)
trap 'rm -rf "$JANUS_TMPDIR"' EXIT

info "Downloading ${BINARY_NAME} ${VERSION} for ${TARGET}..."
curl -sSfL "${DOWNLOAD_URL}" -o "${JANUS_TMPDIR}/${ARCHIVE}"
curl -sSfL "${CHECKSUMS_URL}" -o "${JANUS_TMPDIR}/checksums.sha256"

# Verify checksum before extracting.
verify_checksum "${JANUS_TMPDIR}/${ARCHIVE}" "${JANUS_TMPDIR}/checksums.sha256"

# Extract and install the binary.
tar xzf "${JANUS_TMPDIR}/${ARCHIVE}" -C "${JANUS_TMPDIR}"
install -m 755 "${JANUS_TMPDIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

# On macOS, also install entitlements.plist for codesign.
if [ "${OS}" = "apple-darwin" ] && [ -f "${JANUS_TMPDIR}/entitlements.plist" ]; then
  install -m 644 "${JANUS_TMPDIR}/entitlements.plist" "${INSTALL_DIR}/janus-entitlements.plist"
fi

# Verify the installed binary works.
info "Installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
if "${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null; then
  :
else
  info "WARNING: ${BINARY_NAME} was installed but could not be executed."
  info "On macOS, you may need to allow it in System Preferences > Privacy & Security."
fi

post_install_hints
