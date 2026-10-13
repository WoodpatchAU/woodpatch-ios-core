#!/bin/bash
# mac-test.sh: test WoodpatchCore on the Mac build host, run from the Linux dev box.
#   bundle HEAD → scp → clone on the Mac → `xcodebuild test` the package in an iOS
#   Simulator → per-device counts from the result bundle (zero tests = FAILURE) →
#   openssl interop: `openssl req -verify` on the Secure-Enclave-signed CSR the test
#   suite wrote out (Apple-Silicon Simulators create real enclave keys).
# Env: MAC_HOST (REQUIRED, the Mac's LAN address), SSH_KEY (default: the role key),
#      SIM (default "iPhone 17").
set -euo pipefail
MAC_HOST="${MAC_HOST:?set MAC_HOST to the Mac build host address}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/$(id -un)_ed25519}"
SIM="${SIM:-iPhone 17}"
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
  xcodebuild test -scheme WoodpatchCore -destination 'platform=iOS Simulator,name=$SIM' \
    -derivedDataPath ~/pos/core-dd -resultBundlePath \$res >\$log 2>&1; rc=\$?
  grep -E '✘|error:|warning: .*/Sources/|TEST (SUCCEEDED|FAILED)' \$log | tail -40
  xcrun xcresulttool get test-results summary --path \$res --compact \\
    | /usr/bin/python3 \$dir/scripts/xcresult-summary.py 1 || rc=1
  csr=\$(find ~/Library/Developer/CoreSimulator/Devices -name enclave-csr.pem -newer \$marker 2>/dev/null | head -1)
  if [ -n \"\$csr\" ]; then
    /opt/homebrew/bin/openssl req -in \"\$csr\" -verify -noout 2>&1 | sed 's/^/  interop: /' || rc=1
    rm -f \"\$csr\"
  else
    echo '  interop: no enclave CSR written (no Secure Enclave in this Simulator?): NOT verified'
  fi
  rm -rf \$dir \$res \$marker
  echo \"(full log on the Mac: \$log)\"
  exit \$rc"
