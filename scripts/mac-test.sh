#!/bin/bash
# mac-test.sh: test WoodpatchCore on the Mac build host, run from the Linux dev box.
#   bundle HEAD → scp → clone on the Mac →
#   1. `xcodebuild build` of the SwiftPM package (how the apps consume it);
#   2. the test suite HOSTED in Tests/Host's throwaway app (unhosted SwiftPM test
#      bundles get -34018 from every keychain call in the Simulator), with per-test
#      time limits so a hang fails rather than stalls;
#   → per-device counts from the result bundle (zero tests = FAILURE) →
#   openssl interop: `openssl req -verify` on the CSRs the suite wrote out, the
#   software-key one (EVERY run) and the Secure-Enclave one (Apple-Silicon Simulators
#   have a real enclave). A missing CSR is a FAILURE, not a "not verified" note.
# Env: MAC_HOST (REQUIRED, the Mac's LAN address), SSH_KEY (default: the role key),
#      SIM (default "iPhone 17"), REQUIRE_ENCLAVE (default 1; 0 only for a
#      destination known to have no enclave).
set -euo pipefail
MAC_HOST="${MAC_HOST:?set MAC_HOST to the Mac build host address}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/$(id -un)_ed25519}"
SIM="${SIM:-iPhone 17}"
REQUIRE_ENCLAVE="${REQUIRE_ENCLAVE:-1}"
[[ "$REQUIRE_ENCLAVE" =~ ^[01]$ ]] || { echo "REQUIRE_ENCLAVE must be 0 or 1" >&2; exit 2; }
[[ "$SIM" =~ ^[A-Za-z0-9\ ()._-]+$ ]] || { echo "unsafe simulator name: $SIM" >&2; exit 2; }

repo="$(git rev-parse --show-toplevel)"
sha="$(git -C "$repo" rev-parse --short HEAD)"
[ -n "$(git -C "$repo" status --porcelain)" ] && echo "note: uncommitted changes are NOT tested (bundle = HEAD $sha)"
bundle="$(mktemp -d)/core-$sha.bundle"
git -C "$repo" bundle create "$bundle" HEAD 2>/dev/null
scp -q -o BatchMode=yes -i "$SSH_KEY" "$bundle" "claude@$MAC_HOST:/tmp/core-$sha.bundle"
rm -rf "$(dirname "$bundle")"
echo "testing WoodpatchCore @ $sha on $MAC_HOST ($SIM)…"

# shellcheck disable=SC2029
ssh -i "$SSH_KEY" -o BatchMode=yes "claude@$MAC_HOST" "set -o pipefail
  dir=~/pos/core-$sha log=~/pos/core-$sha.log res=~/pos/core-$sha.xcresult
  rm -rf \$dir \$res && git -c advice.detachedHead=false clone -q /tmp/core-$sha.bundle \$dir && rm -f /tmp/core-$sha.bundle
  marker=\$(mktemp); cd \$dir
  if ! xcodebuild build -scheme WoodpatchCore -destination 'generic/platform=iOS Simulator' \
       -derivedDataPath ~/pos/core-dd >\$log.spm 2>&1; then
    echo '  SwiftPM build FAILED:'; grep -E 'error:' \$log.spm | head -20; rm -rf \$dir; exit 1
  fi
  echo '  SwiftPM package build: OK'
  cd Tests/Host && /opt/homebrew/bin/xcodegen generate >/dev/null
  xcodebuild test -project CoreTests.xcodeproj -scheme CoreTests -destination 'platform=iOS Simulator,name=$SIM' \
    -test-timeouts-enabled YES -maximum-test-execution-time-allowance 60 \
    -derivedDataPath ~/pos/core-dd-hosted -resultBundlePath \$res >\$log 2>&1; rc=\$?
  grep -E '✘|error:|warning: .*/Sources/|TEST (SUCCEEDED|FAILED)' \$log | tail -40
  xcrun xcresulttool get test-results summary --path \$res --compact \\
    | /usr/bin/python3 \$dir/scripts/xcresult-summary.py 1 || rc=1
  for name in software-csr enclave-csr; do
    csr=\$(find ~/Library/Developer/CoreSimulator/Devices -name \$name.pem -newer \$marker 2>/dev/null | head -1)
    if [ -n \"\$csr\" ]; then
      /opt/homebrew/bin/openssl req -in \"\$csr\" -verify -noout 2>&1 | sed \"s/^/  interop \$name: /\" || rc=1
      rm -f \"\$csr\"
    elif [ \$name = enclave-csr ] && [ $REQUIRE_ENCLAVE = 0 ]; then
      echo \"  interop \$name: not expected here (REQUIRE_ENCLAVE=0)\"
    else
      echo \"  interop \$name: MISSING, so NOT verified (failure)\"; rc=1
    fi
  done
  rm -rf \$dir \$res \$marker
  echo \"(full log on the Mac: \$log)\"
  exit \$rc"
