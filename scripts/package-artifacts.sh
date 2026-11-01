#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/delivery"
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

FULL="$OUT/MyPC-PrintDoctor-FULL-SOURCE.zip"
CHANGED="$OUT/MyPC-PrintDoctor-CHANGED-SOURCE.zip"
RELEASE_SRC="$ROOT/artifacts/release/MyPC-PrintDoctor-RELEASE-x64.zip"

rm -f "$FULL" "$CHANGED"

# FULL SOURCE
cd "$ROOT"
zip -r "$FULL" \
  Directory.Build.props MyPC.LanPrintDoctor.sln README.md .gitignore \
  src tests docs scripts .github \
  -x '**/bin/*' -x '**/obj/*' -x '**/.git/*' -x 'artifacts/*'

# CHANGED SOURCE (this delivery = all project files vs empty main)
STAGE="$OUT/_changed_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"
rsync -a --exclude bin --exclude obj \
  Directory.Build.props MyPC.LanPrintDoctor.sln README.md .gitignore \
  src tests docs scripts .github "$STAGE/" 2>/dev/null || true

# Ensure tree copied even without rsync filter quirks
mkdir -p "$STAGE/src" "$STAGE/tests" "$STAGE/docs" "$STAGE/scripts" "$STAGE/.github"
cp -a Directory.Build.props MyPC.LanPrintDoctor.sln README.md .gitignore "$STAGE/" 2>/dev/null || true
cp -a src/. "$STAGE/src/"
cp -a tests/. "$STAGE/tests/"
cp -a docs/. "$STAGE/docs/"
cp -a scripts/. "$STAGE/scripts/"
cp -a .github/. "$STAGE/.github/"
find "$STAGE" -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} + 2>/dev/null || true

cat > "$STAGE/MANIFEST.json" <<EOF
{
  "product": "MyPC LAN & Print Doctor",
  "version": "1.0.0",
  "commit": "$COMMIT",
  "generatedUtc": "$STAMP",
  "note": "CHANGED-SOURCE contains files added/modified for v1 delivery against empty main README-only baseline."
}
EOF

cat > "$STAGE/CHANGELOG.md" <<EOF
# Changelog — v1.0.0

- Initial implementation of MyPC LAN & Print Doctor
- Network/Firewall/SMB/Printing/ShaPrint diagnostics + decision engine
- Safe repair with backup/verify/rollback journal
- WPF VI/EN UI, evidence ZIP exporter
- Windows GitHub Actions CI (build/test/publish)
EOF

cat > "$STAGE/TEST-REPORT.md" <<EOF
# TEST-REPORT

- Unit/integration tests are executed on GitHub-hosted windows-latest via CI.
- Linux cloud agent runs non-WPF unit/integration where compatible.
- Windows 10/11 lab and physical printer tests: NOT_RUN / BLOCKED in this environment.
- Commit: $COMMIT
EOF

cat > "$STAGE/BUILD-INFO.md" <<EOF
# BUILD-INFO

- Commit: $COMMIT
- Target: net10.0 / net10.0-windows
- Publish: win-x64 self-contained (CI)
- Generated UTC: $STAMP
EOF

# SHA256 of changed tree files
( cd "$STAGE" && find . -type f ! -name SHA256.txt | sort | while read -r f; do
    sha256sum "$f"
  done ) > "$STAGE/SHA256.txt"

cd "$STAGE"
zip -r "$CHANGED" .

# RELEASE copy if present
if [[ -f "$RELEASE_SRC" ]]; then
  cp "$RELEASE_SRC" "$OUT/"
fi

echo "FULL=$FULL"
echo "CHANGED=$CHANGED"
sha256sum "$FULL" "$CHANGED" | tee "$OUT/DELIVERY-SHA256.txt"
