#!/usr/bin/env bash
#
# Build the downloadable Linux packages into release/.
#
# Produces the three artifacts a Linux user actually installs:
#
#   * .deb      - Debian, Ubuntu, Mint
#   * .rpm      - Fedora, RHEL, Rocky, Alma
#   * .AppImage - any distro, no install
#
# Run this on Linux. The bundles link against the host's WebKitGTK, so they
# cannot be cross-compiled from Windows or macOS.
#
# Build on the OLDEST distro you intend to support. The binary records the glibc
# symbols it needs, so a package built on Ubuntu 24.04 will not install on
# Ubuntu 22.04. The shipped packages are built on Ubuntu 22.04 (glibc 2.35).
#
# Usage:
#   ./scripts/build-release-linux.sh              # all three bundles
#   ./scripts/build-release-linux.sh deb          # just the .deb
#
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release="$root/release"
mkdir -p "$release"

# Strip a trailing CR so the script works whether package.json uses LF or CRLF
# line endings (a Windows checkout keeps CRLF, which breaks a plain `$` match).
version="$(sed -n 's/^  "version": "\(.*\)",\r\?$/\1/p' "$root/package.json" | head -1)"
if [[ -z "$version" ]]; then
    echo "could not read the version from package.json" >&2
    exit 1
fi
echo "Building Shadow720 $version for Linux"

bundles="${1:-deb,rpm,appimage}"

cd "$root"
npx tauri build --bundles "$bundles"

bundle_dir="$root/src-tauri/target/release/bundle"

stage() {
    local source="$1"
    if [[ -f "$source" ]]; then
        cp "$source" "$release/"
        echo "  staged $(basename "$source")"
    fi
}

stage "$bundle_dir/deb/Shadow720_${version}_amd64.deb"
stage "$bundle_dir/rpm/Shadow720-${version}-1.x86_64.rpm"
stage "$bundle_dir/appimage/Shadow720_${version}_amd64.AppImage"

# The AppImage is useless without the execute bit, and copying it across a
# filesystem that does not carry permissions (a Windows share, a FAT stick)
# drops it.
chmod +x "$release/Shadow720_${version}_amd64.AppImage" 2>/dev/null || true

echo
echo "Artifacts in $release"
ls -la "$release" | grep -E '\.(deb|rpm|AppImage)$' || true
