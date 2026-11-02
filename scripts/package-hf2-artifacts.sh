#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/delivery-hf2"
BASELINE="${1:-6ed5d1c2e7853baf720fbdd74311bbf38fed85ec}"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CI_URL="${CI_URL:-PENDING}"
EXE_SHA="${EXE_SHA:-PENDING}"
ZIP_SHA="${ZIP_SHA:-PENDING}"
mkdir -p "$OUT"
FULL="$OUT/MyPC-PrintDoctor-P22-HF2-FULL-SOURCE.zip"
CHANGED="$OUT/MyPC-PrintDoctor-P22-HF2-CHANGED-SOURCE.zip"
RELEASE="$OUT/MyPC-PrintDoctor-P22-HF2-RELEASE-x64.zip"
rm -f "$FULL" "$CHANGED" "$RELEASE" "$OUT/RELEASE_BLOCKED.txt" "$OUT/SHA256.txt"

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

PUB="$ROOT/artifacts/publish/win-x64"; mkdir -p "$PUB"
set +e
dotnet publish "$ROOT/src/MyPC.LanPrintDoctor/MyPC.LanPrintDoctor.csproj" \
  -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -o "$PUB" >"$OUT/publish.log" 2>&1
PUB_EC=$?
set -e
EXE="$PUB/MyPC.LanPrintDoctor.exe"
if [[ $PUB_EC -eq 0 && -f "$EXE" ]] && find "$PUB" \( -name 'coreclr.dll' -o -name 'System.Private.CoreLib.dll' \) | grep -q .; then
  (cd "$PUB" && zip -rq "$RELEASE" .)
  EXE_SHA="$(sha256sum "$EXE" | awk '{print $1}')"
  ZIP_SHA="$(sha256sum "$RELEASE" | awk '{print $1}')"
else
  echo "RELEASE_BLOCKED: prefer Windows CI artifact — do not ship Linux-cross publish as field EXE" | tee "$OUT/RELEASE_BLOCKED.txt"
fi

cat > "$OUT/MANIFEST.json" <<EOF
{
  "product": "MyPC LAN & Print Doctor",
  "phase": "P22-HF2",
  "version": "1.2.2-HF2",
  "baselineCommit": "$BASELINE",
  "commit": "$COMMIT",
  "ciUrl": "$CI_URL",
  "exeSha256": "$EXE_SHA",
  "releaseZipSha256": "$ZIP_SHA",
  "generatedUtc": "$STAMP",
  "publishSingleFile": false,
  "fieldReady": false,
  "fieldValidation": "NOT_RUN",
  "uiVisualLab": "UI_VISUAL_LAB_NOT_RUN"
}
EOF

cp -a docs/CHANGELOG-HF2.md "$OUT/CHANGELOG.md"
cp -a docs/UI-DEFECT-FIX-REPORT.md "$OUT/UI-DEFECT-FIX-REPORT.md"
cp -a docs/SCAN-DIAGNOSTICS-TEST-REPORT.md "$OUT/SCAN-DIAGNOSTICS-TEST-REPORT.md"
cp -a docs/BUILD-INFO-HF2.md "$OUT/BUILD-INFO.md"

{
  echo "HEAD $COMMIT"
  echo "CI_URL $CI_URL"
  echo "EXE_SHA256 $EXE_SHA"
  echo "RELEASE_ZIP_SHA256 $ZIP_SHA"
  sha256sum "$FULL" "$CHANGED" 2>/dev/null || true
  [[ -f "$RELEASE" ]] && sha256sum "$RELEASE" || true
} | tee "$OUT/SHA256.txt"

echo "HF2 packages written to $OUT"
