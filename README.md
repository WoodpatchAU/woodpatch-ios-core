# woodpatch-ios-core

`WoodpatchCore`: the app-agnostic iOS foundation shared by Woodpatch's two native apps, the
softphone (`woodpatch-mobile-app`) and the POS (`woodpatch-pos-app`). Tracking: BOS
[#2562](https://github.com/WoodpatchAU/woodpatch-business-operating-system/issues/2562).

## The rules (load-bearing)

- **No payments, Stripe or POS code. Ever.** That keeps this package, and the softphone that
  consumes it, out of PCI scope.
- **No telephony or comms code either.** Each app keeps its own pairing, credentials, endpoints
  and error-code enums.
- **Nothing app-specific is derived here.** Keychain service ids, accessibility classes, log
  subsystems and pinned hosts are all supplied by the app. (A derived keychain service id once
  silently unpaired every installed softphone: #810/#817.)
- **Vendored, not fetched.** Each app copies this package in at a **pinned commit**, with the
  commit plus a tree hash recorded and checked in CI. The Mac build host has no GitHub key, so a
  remote SwiftPM dependency won't resolve there.

Write access: frontend-pos, frontend-ios. Changes are reviewed by the other app's owner; the
reviewer does a security pass on pinning and keychain changes.
