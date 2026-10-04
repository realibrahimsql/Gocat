#!/usr/bin/env bash
# Builds macOS-native packages (DMG + PKG installer) for a release.
# Runs ONLY on macOS (needs hdiutil + pkgbuild). Linux CI produces
# tarballs, deb and rpm; this script adds the Apple artifacts.
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS only, skipping" >&2
  exit 0
fi

version="${1:-dev}"
package_version="${version#v}"
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_dir="$root_dir/release"
mkdir -p "$release_dir"

build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
git_commit="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || echo unknown)"
ldflags="-s -w -X main.version=$version -X main.buildTime=$build_time -X main.gitCommit=$git_commit -X main.gitBranch=main -X main.builtBy=github-actions"

for goarch in amd64 arm64; do
  stage="$root_dir/dist/macos-$goarch"
  rm -rf "$stage"
  mkdir -p "$stage"
  GOOS=darwin GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags="$ldflags" -o "$stage/gocat" "$root_dir"
  cp "$root_dir/README.md" "$root_dir/LICENSE" "$stage/"

  dmg="$release_dir/gocat-${version}-darwin-${goarch}.dmg"
  rm -f "$dmg"
  hdiutil create -volname "GoCat $version" -srcfolder "$stage" -ov -format UDZO "$dmg"

  pkg_stage="$root_dir/dist/pkgroot-$goarch"
  rm -rf "$pkg_stage"
  mkdir -p "$pkg_stage/usr/local/bin"
  cp "$stage/gocat" "$pkg_stage/usr/local/bin/gocat"
  chmod 0755 "$pkg_stage/usr/local/bin/gocat"
  pkgbuild --root "$pkg_stage" --identifier dev.gocat.cli \
    --version "$package_version" --install-location / \
    "$release_dir/gocat-${version}-darwin-${goarch}.pkg"

  rm -rf "$stage" "$pkg_stage"
done

echo "macOS packages in $release_dir:"
ls -la "$release_dir"/*.dmg "$release_dir"/*.pkg
