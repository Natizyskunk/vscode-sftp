#!/usr/bin/env bash
# Render docs/home.md as the GitHub wiki's Home.md.
#
# Repo-relative links (../CONTRIBUTING.md, ./setting.md, ...) don't resolve
# on the wiki, so they are rewritten to absolute GitHub blob URLs.
#
# Usage: scripts/sync-wiki.sh [src] [dest]
set -euo pipefail

src=${1:-docs/home.md}
dest=${2:-wiki/Home.md}
repo_url="https://github.com/jmwerk/vscode-sftp/blob/develop"

sed \
  -e "s#](\.\./#](${repo_url}/#g" \
  -e "s#](\./#](${repo_url}/docs/#g" \
  "$src" > "$dest"

echo "Wrote $dest from $src"
