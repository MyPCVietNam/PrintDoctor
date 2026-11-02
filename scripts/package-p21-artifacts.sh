#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/delivery-p21"
BASELINE="${1:-f31a7dff9e8ca8490f557a8740761a4ae6e6291a}"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"
FULL="$OUT/MyPC-PrintDoctor-P21-FULL-SOURCE.zip"
CHANGED="$OUT/MyPC-PrintDoctor-P21-CHANGED-SOURCE.zip"
RELEASE="$OUT/MyPC-PrintDoctor-P21-RELEASE-x64.zip"
FIELD="$OUT/MyPC-PrintDoctor-P21-FIELD-TEST-KIT.zip"
SIM="$OUT/MyPC-PrintDoctor-P21-SIMULATION-TEST.zip"
rm -f "$FULL" "$CHANGED" "$RELEASE" "$FIELD" "$SIM" "$OUT/RELEASE_BLOCKED.txt"

cd "$ROOT"
zip -rq "$FULL" Directory.Build.props MyPC.LanPrintDoctor.sln README.md .gitignore src tests docs scripts .github \
  -x '**/bin/*' -x '**/obj/*' -x '**/.git/*' -x 'artifacts/*'

STAGE="$OUT/_changed_stage"; rm -rf "$STAGE"; mkdir -p "$STAGE"
mapfile -t FILES < <(git diff --name-only --diff-filter=ACMRT "$BASELINE" HEAD)
while IFS= read -r f; do FILES+=("$f"); done < <(git ls-files --others --exclude-standard)
mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | awk 'NF' | sort -u)
for f in "${FILES[@]}"; do
  [[ -f "$ROOT/$f" ]] || continue
  mkdir -p "$STAGE/$(dirname "$f")"
  cp -a "$ROOT/$f" "$STAGE/$f"
done
(cd "$STAGE" && zip -rq "$CHANGED" .)

KIT="$OUT/_field_kit"; rm -rf "$KIT"; mkdir -p "$KIT"
cp -a docs/FIELD-TEST-CHECKLIST-P21.md "$KIT/" 2>/dev/null || true
cp -a docs/p21/FIELD-PLAYBOOK-20261102.md "$KIT/" 2>/dev/null || true
cp -a docs/KNOWN-LIMITATIONS.md "$KIT/" 2>/dev/null || true
cp -a tests/Simulation/windows-readonly "$KIT/windows-readonly" 2>/dev/null || true
(cd "$KIT" && zip -rq "$FIELD" .)

SIMS="$OUT/_sim"; rm -rf "$SIMS"; mkdir -p "$SIMS"
cp -a tests/Simulation "$SIMS/" 2>/dev/null || true
cp -a docs/SIMULATION-*.md docs/FAULT-INJECTION-REPORT.md "$SIMS/" 2>/dev/null || true
(cd "$SIMS" && zip -rq "$SIM" .)

PUB="$ROOT/artifacts/publish/win-x64"; mkdir -p "$PUB"
set +e
dotnet publish "$ROOT/src/MyPC.LanPrintDoctor/MyPC.LanPrintDoctor.csproj" \
  -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o "$PUB" >"$OUT/publish.log" 2>&1
PUB_EC=$?
set -e
EXE="$PUB/MyPC.LanPrintDoctor.exe"
if [[ $PUB_EC -eq 0 && -f "$EXE" ]] && find "$PUB" \( -name 'coreclr.dll' -o -name 'System.Private.CoreLib.dll' \) | grep -q .; then
  (cd "$PUB" && zip -rq "$RELEASE" .)
else
  echo "RELEASE_BLOCKED: prefer Windows CI artifact" | tee "$OUT/RELEASE_BLOCKED.txt"
fi

CI_URL="${CI_URL:-PENDING}"
cat > "$OUT/MANIFEST.json" <<EOF
{
  "product": "MyPC LAN & Print Doctor",
  "phase": "P21-RC2",
  "version": "1.2.1-RC2",
  "baselineCommit": "$BASELINE",
  "commit": "$COMMIT",
  "ciUrl": "$CI_URL",
  "generatedUtc": "$STAMP",
  "publishSingleFile": false,
  "fieldReady": false,
  "fieldValidation": "PENDING"
}
EOF
cp -a docs/CHANGELOG-P21.md "$OUT/CHANGELOG.md"
cp -a docs/DEFECT-FIX-MATRIX.md "$OUT/DEFECT-FIX-MATRIX.md"
cp -a docs/TEST-REPORT-P21.md "$OUT/TEST-REPORT.md"
cp -a docs/BUILD-INFO-P21.md "$OUT/BUILD-INFO.md"
cp -a docs/SIMULATION-REAL-ENGINE-RESULTS.md "$OUT/"
cp -a docs/SIMULATION-MAPPING.md "$OUT/"
cp -a docs/FAULT-INJECTION-REPORT.md "$OUT/"
cp -a docs/WINDOWS-API-VALIDATION.md "$OUT/"
cp -a docs/KNOWN-LIMITATIONS.md "$OUT/"
cp -a docs/FIELD-TEST-CHECKLIST-P21.md "$OUT/FIELD-TEST-CHECKLIST.md"
{
  echo "commit=$COMMIT"; echo "baseline=$BASELINE"; echo "ciUrl=$CI_URL"
  for z in "$FULL" "$CHANGED" "$RELEASE" "$FIELD" "$SIM"; do [[ -f "$z" ]] && sha256sum "$z"; done
} | tee "$OUT/SHA256.txt"
echo "P21 packaging → $OUT"; ls -la "$OUT"
