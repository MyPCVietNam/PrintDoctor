#!/usr/bin/env bash
# Package P2 v1.2.0-RC1 delivery artifacts against verified PR #2 HEAD baseline.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/delivery-p2"
BASELINE="${1:-096297248f904ec60467a2522d5dfced8cece1f7}"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT" "$ROOT/artifacts/release"

FULL="$OUT/MyPC-PrintDoctor-P2-FULL-SOURCE.zip"
CHANGED="$OUT/MyPC-PrintDoctor-P2-CHANGED-SOURCE.zip"
RELEASE="$OUT/MyPC-PrintDoctor-P2-RELEASE-x64.zip"
FIELD="$OUT/MyPC-PrintDoctor-P2-FIELD-TEST-KIT.zip"

rm -f "$FULL" "$CHANGED" "$RELEASE" "$FIELD"
rm -f "$OUT/RELEASE_BLOCKED.txt"

# --- FULL SOURCE ---
cd "$ROOT"
zip -rq "$FULL" \
  Directory.Build.props MyPC.LanPrintDoctor.sln README.md .gitignore \
  src tests docs scripts .github \
  -x '**/bin/*' -x '**/obj/*' -x '**/.git/*' -x 'artifacts/*'

# --- CHANGED SOURCE (vs baseline) ---
STAGE="$OUT/_changed_stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cd "$ROOT"
mapfile -t FILES < <(git diff --name-only --diff-filter=ACMRT "$BASELINE" HEAD)
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  FILES+=("$f")
done < <(git ls-files --others --exclude-standard)
mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | awk 'NF' | sort -u)

for f in "${FILES[@]}"; do
  [[ -f "$ROOT/$f" ]] || continue
  mkdir -p "$STAGE/$(dirname "$f")"
  cp -a "$ROOT/$f" "$STAGE/$f"
done

for doc in DEFECT-FIX-MATRIX.md CHANGELOG-P11.md TEST-REPORT-P11.md BUILD-INFO-P11.md FIELD-TEST-CHECKLIST-P2.md; do
  if [[ -f "$ROOT/docs/$doc" ]]; then
    mkdir -p "$STAGE/docs"
    cp -a "$ROOT/docs/$doc" "$STAGE/docs/$doc"
  fi
done

cd "$STAGE"
zip -rq "$CHANGED" .

# --- FIELD TEST KIT ---
KIT="$OUT/_field_kit"
rm -rf "$KIT"
mkdir -p "$KIT"
cp -a "$ROOT/docs/FIELD-TEST-CHECKLIST-P2.md" "$KIT/FIELD-TEST-CHECKLIST.md"
cp -a "$ROOT/docs/RUNBOOK.md" "$KIT/RUNBOOK.md" 2>/dev/null || true
cp -a "$ROOT/docs/CHANGELOG-P11.md" "$KIT/CHANGELOG.md"
cp -a "$ROOT/docs/BUILD-INFO-P11.md" "$KIT/BUILD-INFO.md"
cat > "$KIT/README-FIELD.md" <<'EOF'
# MyPC PrintDoctor v1.2.0-RC1 — Field Test Kit

FIELD_VALIDATION_PENDING until office Windows 10/11 runs complete.

1. Use RELEASE ZIP from Windows CI (multi-file self-contained — not single-file).
2. Follow FIELD-TEST-CHECKLIST.md exactly (one repair at a time).
3. Collect BEFORE/AFTER evidence ZIPs from the app Export action.
4. If INFRASTRUCTURE_ACTION_REQUIRED appears — do not spam firewall repairs.
5. Rollback only transaction-owned MyPC.PrintDoctor.* / journal-backed changes.
EOF
(cd "$KIT" && zip -rq "$FIELD" .)

# --- RELEASE: only real publish with EXE verification ---
PUB="$ROOT/artifacts/publish/win-x64"
mkdir -p "$PUB"
set +e
dotnet publish "$ROOT/src/MyPC.LanPrintDoctor/MyPC.LanPrintDoctor.csproj" \
  -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false \
  -o "$PUB" >"$OUT/publish.log" 2>&1
PUB_EC=$?
set -e

EXE="$PUB/MyPC.LanPrintDoctor.exe"
if [[ $PUB_EC -eq 0 && -f "$EXE" ]]; then
  if ! find "$PUB" -name 'coreclr.dll' -o -name 'System.Private.CoreLib.dll' | grep -q .; then
    echo "RELEASE_BLOCKED: publish output missing runtime dependencies" | tee "$OUT/RELEASE_BLOCKED.txt"
  else
    ( cd "$PUB" && zip -rq "$RELEASE" . )
    echo "PublishSingleFile=false — self-contained multi-file release (EXE + runtime deps)." > "$OUT/RELEASE-NOTE.txt"
    sha256sum "$EXE" | tee -a "$OUT/RELEASE-NOTE.txt"
  fi
else
  echo "RELEASE_BLOCKED: Windows publish failed or EXE missing (exit=$PUB_EC)." | tee "$OUT/RELEASE_BLOCKED.txt"
  echo "Authoritative RELEASE ZIP comes from GitHub windows-latest CI artifacts." >> "$OUT/RELEASE_BLOCKED.txt"
fi

CI_URL="${CI_URL:-PENDING}"
WINDOWS_CI_PASS="${WINDOWS_CI_PASS:-PENDING}"

cat > "$OUT/MANIFEST.json" <<EOF
{
  "product": "MyPC LAN & Print Doctor",
  "phase": "P2-RC1-FIELD-PILOT",
  "version": "1.2.0-RC1",
  "baselineCommit": "$BASELINE",
  "commit": "$COMMIT",
  "ciUrl": "$CI_URL",
  "generatedUtc": "$STAMP",
  "publishSingleFile": false,
  "publishShape": "self-contained multi-file win-x64",
  "fieldReady": false,
  "fieldValidation": "PENDING",
  "releasePresent": $( [[ -f "$RELEASE" ]] && echo true || echo false ),
  "releaseAuthority": "GitHub Actions windows-latest artifact preferred",
  "artifacts": [
    "MyPC-PrintDoctor-P2-FULL-SOURCE.zip",
    "MyPC-PrintDoctor-P2-CHANGED-SOURCE.zip",
    "MyPC-PrintDoctor-P2-RELEASE-x64.zip",
    "MyPC-PrintDoctor-P2-FIELD-TEST-KIT.zip",
    "MANIFEST.json",
    "CHANGELOG.md",
    "DEFECT-FIX-MATRIX.md",
    "TEST-REPORT.md",
    "BUILD-INFO.md",
    "SHA256.txt"
  ]
}
EOF

cp -a "$ROOT/docs/CHANGELOG-P11.md" "$OUT/CHANGELOG.md"
cp -a "$ROOT/docs/DEFECT-FIX-MATRIX.md" "$OUT/DEFECT-FIX-MATRIX.md"
cp -a "$ROOT/docs/TEST-REPORT-P11.md" "$OUT/TEST-REPORT.md"
cp -a "$ROOT/docs/BUILD-INFO-P11.md" "$OUT/BUILD-INFO.md"

{
  echo "commit=$COMMIT"
  echo "baseline=$BASELINE"
  echo "ciUrl=$CI_URL"
  echo "windowsCiPass=$WINDOWS_CI_PASS"
  for z in "$FULL" "$CHANGED" "$RELEASE" "$FIELD"; do
    [[ -f "$z" ]] || continue
    sha256sum "$z"
  done
  [[ -f "$EXE" ]] && sha256sum "$EXE" || true
} | tee "$OUT/SHA256.txt"

echo "P2 packaging complete → $OUT"
ls -la "$OUT"
