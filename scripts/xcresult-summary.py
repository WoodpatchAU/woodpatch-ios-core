#!/usr/bin/env python3
"""Print per-device test counts from `xcresulttool get test-results summary --compact`
(JSON on stdin). Exit 1 if any device ran ZERO tests or had a failure, or if the
number of devices isn't the expected one (argv[1], default 2: iPhone + iPad), so
"TEST SUCCEEDED" with nothing executed, or a silently dropped destination, can't
pass. Used by mac-test.sh.
Runs on the Mac's /usr/bin/python3 (3.9), so no 3.10+ syntax."""
import json
import sys

expected_devices = int(sys.argv[1]) if len(sys.argv) > 1 else 2
summary = json.load(sys.stdin)
bad = False
for entry in summary.get("devicesAndConfigurations", []):
    name = entry["device"]["deviceName"]
    passed, failed, skipped = entry["passedTests"], entry["failedTests"], entry["skippedTests"]
    bad = bad or passed == 0 or failed > 0
    print("  %s: %d passed, %d failed, %d skipped" % (name, passed, failed, skipped))
devices = len(summary.get("devicesAndConfigurations", []))
if devices != expected_devices:
    bad = True
    print("  expected %d devices, the result bundle has %d" % (expected_devices, devices))
print("  result: %s (%s distinct tests)" % (summary.get("result"), summary.get("totalTestCount")))
sys.exit(1 if bad else 0)
