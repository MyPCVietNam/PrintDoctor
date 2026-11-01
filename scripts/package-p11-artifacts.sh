#!/usr/bin/env bash
# Package P1.1 delivery artifacts against baseline commit (merged PR #1).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/artifacts/delivery-p11"
BASELINE="${1:-1647875}"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT" "$ROOT/artifacts/release"

FULL="$OUT/MyPC-PrintDoctor-P11-FULL-SOURCE.zip"
CHANGED="$OUT/MyPC-PrintDoctor-P11-CHANGED-SOURCE.zip"
RELEASE="$OUT/MyPC-PrintDoctor-P11-RELEASE-x64.zip"

rm -f "$FULL" "$CHANGED" "$RELEASE"

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
# List changed/added files vs baseline (tracked + untracked via status after commit)
mapfile -t FILES < <(git diff --name-only --diff-filter=ACMRT "$BASELINE" HEAD)
# Also include untracked if any remain
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  FILES+=("$f")
done < <(git ls-files --others --exclude-standard)

# Deduplicate
mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | awk 'NF' | sort -u)

for f in "${FILES[@]}"; do
  [[ -f "$ROOT/$f" ]] || continue
  mkdir -p "$STAGE/$(dirname "$f")"
  cp -a "$ROOT/$f" "$STAGE/$f"
done

# Always include delivery docs at docs/ root for the package
for doc in DEFECT-FIX-MATRIX.md CHANGELOG-P11.md TEST-REPORT-P11.md BUILD-INFO-P11.md MANIFEST-P11.json; do
  if [[ -f "$ROOT/docs/$doc" ]]; then
    mkdir -p "$STAGE/docs"
    cp -a "$ROOT/docs/$doc" "$STAGE/docs/$doc"
  fi
done

cd "$STAGE"
zip -rq "$CHANGED" .

# --- RELEASE: attempt publish (may be multi-file self-contained; WPF needs windows targeting) ---
PUB="$ROOT/artifacts/publish/win-x64"
mkdir -p "$PUB"
set +e
dotnet publish "$ROOT/src/MyPC.LanPrintDoctor/MyPC.LanPrintDoctor.csproj" \
  -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false \
  -o "$PUB" 2>"$OUT/publish.log"
PUB_EC=$?
set -e

if [[ $PUB_EC -eq 0 && -d "$PUB" ]]; then
  (
    cd "$PUB"
    zip -rq "$RELEASE" .
  )
  # Annotate: multi-file self-contained, not single EXE
  echo "PublishSingleFile=false — self-contained multi-file release (MyPC.LanPrintDoctor.exe + runtime deps)." > "$OUT/RELEASE-NOTE.txt"
else
  echo "Publish blocked/failed on this host (exit=$PUB_EC). See publish.log. RELEASE ZIP will be produced by Windows CI." | tee "$OUT/RELEASE-NOTE.txt"
  # Minimal stub so delivery lists the artifact name with explanation
  echo "WINDOWS_CI_REQUIRED" > "$OUT/RELEASE-PLACEHOLDER.txt"
  zip -jq "$RELEASE" "$OUT/RELEASE-PLACEHOLDER.txt" "$OUT/RELEASE-NOTE.txt" "$OUT/publish.log"
fi

# --- Manifests / hashes ---
cat > "$OUT/MANIFEST.json" <<EOF
{
  "product": "MyPC LAN & Print Doctor",
  "phase": "P1.1",
  "version": "1.1.0",
  "baselineCommit": "$BASELINE",
  "commit": "$COMMIT",
  "generatedUtc": "$STAMP",
  "publishSingleFile": false,
  "publishShape": "self-contained multi-file win-x64",
  "artifacts": [
    "MyPC-PrintDoctor-P11-FULL-SOURCE.zip",
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
    "WINDOWS_CI_PASS": "PENDING",
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
  sha256sum MyPC-PrintDoctor-P11-FULL-SOURCE.zip \
            MyPC-PrintDoctor-P11-CHANGED-SOURCE.zip \
            MyPC-PrintDoctor-P11-RELEASE-x64.zip \
            MANIFEST.json \
            CHANGELOG.md \
            DEFECT-FIX-MATRIX.md \
            TEST-REPORT.md \
            BUILD-INFO.md 2>/dev/null | tee SHA256.txt
)

echo "OUT=$OUT"
ls -la "$OUT"
