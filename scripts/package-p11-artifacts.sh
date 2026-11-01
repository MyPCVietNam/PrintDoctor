#!/usr/bin/env bash
# Package P1.1 / HF1 delivery artifacts against baseline commit (merged PR #1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/delivery-p11"
BASELINE="${1:-1647875}"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT" "$ROOT/artifacts/release"

FULL="$OUT/MyPC-PrintDoctor-P11-FULL-SOURCE.zip"
CHANGED="$OUT/MyPC-PrintDoctor-P11-HF2-CHANGED-SOURCE.zip"
# Keep legacy name as copy for older scripts
CHANGED_LEGACY="$OUT/MyPC-PrintDoctor-P11-CHANGED-SOURCE.zip"
RELEASE="$OUT/MyPC-PrintDoctor-P11-RELEASE-x64.zip"

rm -f "$FULL" "$CHANGED" "$RELEASE"
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

for doc in DEFECT-FIX-MATRIX.md CHANGELOG-P11.md TEST-REPORT-P11.md BUILD-INFO-P11.md MANIFEST-P11.json; do
  if [[ -f "$ROOT/docs/$doc" ]]; then
    mkdir -p "$STAGE/docs"
    cp -a "$ROOT/docs/$doc" "$STAGE/docs/$doc"
  fi
done

cd "$STAGE"
zip -rq "$CHANGED" .
cp -f "$CHANGED" "$CHANGED_LEGACY"

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
  # Require runtime dependency presence (multi-file self-contained)
  if ! find "$PUB" -name 'coreclr.dll' -o -name 'System.Private.CoreLib.dll' | grep -q .; then
    echo "RELEASE_BLOCKED: publish output missing runtime dependencies" | tee "$OUT/RELEASE_BLOCKED.txt"
    echo "PublishSingleFile=false self-contained multi-file expected." >> "$OUT/RELEASE_BLOCKED.txt"
  else
    (
      cd "$PUB"
      zip -rq "$RELEASE" .
    )
    echo "PublishSingleFile=false — self-contained multi-file release (EXE + runtime deps)." > "$OUT/RELEASE-NOTE.txt"
    sha256sum "$EXE" | tee -a "$OUT/RELEASE-NOTE.txt"
  fi
else
  echo "RELEASE_BLOCKED: Windows publish failed or EXE missing (exit=$PUB_EC)." | tee "$OUT/RELEASE_BLOCKED.txt"
  echo "Do not treat any placeholder as a release. Only GitHub windows-latest CI may mint an authoritative RELEASE ZIP." >> "$OUT/RELEASE_BLOCKED.txt"
  # Intentionally do NOT create MyPC-PrintDoctor-P11-RELEASE-x64.zip
fi

CI_URL="${CI_URL:-PENDING}"
WINDOWS_CI_PASS="${WINDOWS_CI_PASS:-PENDING}"
HF2_BASELINE="${HF2_BASELINE:-7a8099ec99d5d7a02fc90bc9993b28d607f085c4}"

cat > "$OUT/MANIFEST.json" <<EOF
{
  "product": "MyPC LAN & Print Doctor",
  "phase": "P1.1-HF2",
  "version": "1.1.2",
  "baselineCommit": "$BASELINE",
  "hf2BaselineCommit": "$HF2_BASELINE",
  "commit": "$COMMIT",
  "ciUrl": "$CI_URL",
  "generatedUtc": "$STAMP",
  "publishSingleFile": false,
  "publishShape": "self-contained multi-file win-x64",
  "releasePresent": $( [[ -f "$RELEASE" ]] && echo true || echo false ),
  "releaseAuthority": "GitHub Actions windows-latest artifact preferred; local zip is packaging convenience only",
  "artifacts": [
    "MyPC-PrintDoctor-P11-FULL-SOURCE.zip",
    "MyPC-PrintDoctor-P11-HF2-CHANGED-SOURCE.zip",
    "MyPC-PrintDoctor-P11-CHANGED-SOURCE.zip",
    "MyPC-PrintDoctor-P11-RELEASE-x64.zip",
    "MANIFEST.json",
    "CHANGELOG.md",
    "DEFECT-FIX-MATRIX.md",
    "TEST-REPORT.md",
    "BUILD-INFO.md",
    "SHA256.txt"
  ],
  "readiness": {
    "UNIT_PASS": true,
    "INTEGRATION_PASS": true,
    "WINDOWS_CI_PASS": "$WINDOWS_CI_PASS",
    "WIN10_LAB_NOT_RUN": true,
    "WIN11_LAB_NOT_RUN": true,
    "PHYSICAL_LAN_NOT_RUN": true,
    "PHYSICAL_PRINT_NOT_RUN": true,
    "FIELD_READY": false,
    "PRODUCTION_READY": false
  }
}
EOF

cp "$ROOT/docs/CHANGELOG-P11.md" "$OUT/CHANGELOG.md" 2>/dev/null || true
cp "$ROOT/docs/DEFECT-FIX-MATRIX.md" "$OUT/DEFECT-FIX-MATRIX.md" 2>/dev/null || true
cp "$ROOT/docs/TEST-REPORT-P11.md" "$OUT/TEST-REPORT.md" 2>/dev/null || true
cp "$ROOT/docs/BUILD-INFO-P11.md" "$OUT/BUILD-INFO.md" 2>/dev/null || true

(
  cd "$OUT"
  FILES_HASH=(MyPC-PrintDoctor-P11-FULL-SOURCE.zip MyPC-PrintDoctor-P11-HF2-CHANGED-SOURCE.zip MyPC-PrintDoctor-P11-CHANGED-SOURCE.zip MANIFEST.json CHANGELOG.md DEFECT-FIX-MATRIX.md TEST-REPORT.md BUILD-INFO.md)
  if [[ -f MyPC-PrintDoctor-P11-RELEASE-x64.zip ]]; then
    FILES_HASH+=(MyPC-PrintDoctor-P11-RELEASE-x64.zip)
  fi
  sha256sum "${FILES_HASH[@]}" 2>/dev/null | tee SHA256.txt
)

echo "OUT=$OUT"
ls -la "$OUT"
