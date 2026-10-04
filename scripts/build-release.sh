#!/usr/bin/env bash

set -euo pipefail

version="${1:-dev}"
package_version="${version#v}"
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="$root_dir/dist"
release_dir="$root_dir/release"

mkdir -p "$dist_dir" "$release_dir"
rm -f "$dist_dir"/* "$release_dir"/*

build_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
git_commit="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || echo unknown)"
git_branch="$(git -C "$root_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
ldflags="-s -w -X main.version=$version -X main.buildTime=$build_time -X main.gitCommit=$git_commit -X main.gitBranch=$git_branch -X main.builtBy=github-actions"

platforms=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "freebsd/amd64"
)

for platform in "${platforms[@]}"; do
  goos="${platform%/*}"
  goarch="${platform#*/}"
  name="gocat-${version}-${goos}-${goarch}"
  binary="gocat"
  archive_ext="tar.gz"
  if [[ "$goos" == "windows" ]]; then
    binary="gocat.exe"
    archive_ext="zip"
  fi

  work_dir="$dist_dir/$name"
  mkdir -p "$work_dir"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags="$ldflags" -o "$work_dir/$binary" "$root_dir"
  cp "$root_dir/README.md" "$root_dir/LICENSE" "$work_dir/"

  if [[ "$archive_ext" == "zip" ]]; then
    (cd "$dist_dir" && zip -qr "$release_dir/$name.zip" "$name")
  else
    tar -C "$dist_dir" -czf "$release_dir/$name.tar.gz" "$name"
  fi
  rm -rf "$work_dir"
done

if command -v dpkg-deb >/dev/null 2>&1; then
  cp "$release_dir/gocat-${version}-linux-amd64.tar.gz" "$dist_dir/linux-amd64.tar.gz"
  tar -C "$dist_dir" -xzf "$dist_dir/linux-amd64.tar.gz"
  cp "$dist_dir/gocat-${version}-linux-amd64/gocat" "$root_dir/gocat"
  chmod +x "$root_dir/gocat"
  (cd "$root_dir/pkg/Debian" && ./build-deb.sh "$package_version" amd64)
  cp "$root_dir/pkg/Debian/"*.deb "$release_dir/"
  rm -f "$root_dir/gocat" "$dist_dir/linux-amd64.tar.gz"
  rm -rf "$dist_dir/gocat-${version}-linux-amd64"
fi

go list -m -json all > "$dist_dir/SBOM.modules.json"

cat > "$dist_dir/PROVENANCE.json" <<EOF
{
  "name": "gocat",
  "version": "$version",
  "package_version": "$package_version",
  "git_commit": "$git_commit",
  "git_branch": "$git_branch",
  "build_time": "$build_time",
  "built_by": "github-actions",
  "platforms": [
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64",
    "windows/amd64",
    "freebsd/amd64"
  ]
}
EOF

(
  cd "$release_dir"
  shasum -a 256 ./* > "$dist_dir/SHA256SUMS"
  md5sum ./* > "$dist_dir/MD5SUMS"
)

cat > "$release_dir/RELEASE_NOTES.md" <<EOF
# GoCat $version

Automated release for $version.

- Commit: $git_commit
- Build time: $build_time
- Platforms: linux, macOS, Windows, FreeBSD
EOF
