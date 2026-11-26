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
  remote SwiftPM dependency won't resolve there. **Vendor `Package.swift` + `Sources/` only**, never
  `Tests/` or `scripts/`: the test fixtures include a (test-only) client private key, and that can
  never be allowed to land in an app target.
- **Identity changes mean a new session.** An app that presents a client identity through
  `TrustPinning.pinnedSession` must `invalidateAndCancel()` and rebuild the session whenever that
  identity changes. Credentials are never cached (`persistence: .none`), but TLS resumption can
  outlive them.

Write access: frontend-pos, frontend-ios. Changes are reviewed by the other app's owner; the
reviewer does a security pass on pinning and keychain changes.

## What's in it (v1)

| File | What | From the softphone |
|---|---|---|
| `Transport.swift` | `URLSession` seam. **v1.14:** `send(_:maxBytes:)`, a REQUIRED second method: the cap holds while the bytes arrive (an announced length over it is refused before the body, a stream past it is cancelled at the byte); `ResponseTooLarge` (carries the cap only) and its `check(_:maxBytes:)` for stubs | was one method; the second has no default on purpose |
| `JSONCoding.swift` | BOS JSON conventions (ISO 8601 ± fractions). **v1.13:** two shared, fixed-option date formatters instead of one per date field (BOS #5481); the same parse, pinned against the old path; public `date(from:)`. **v1.15:** an unparseable date's decode error no longer carries the value | unchanged |
| `APIEnvelope.swift` | `APIEnvelope<Payload, Meta>`, `APIStandardMeta`, `APIPagination`, `APIErrorBody` | meta made generic (apps add their own fields) |
| `APIRefusal.swift` | **v1.16:** when a reply is the SERVER's answer: `requireFromPinnedOrigin` on every reply (https, the pinned host lower-cased with no trailing dot, the pinned port; the final URL after any redirect), and `decode(data:response:pinned:)` for a refusal (the status read from the reply; a 2xx is `.decode`, never a refusal): pinned origin, JSON media type (ASCII case only), the envelope with `success: false` and an `error`, a code of 1-64 `[A-Za-z0-9_]`, the message cut to 500 Unicode scalars and the request id to 128. Otherwise `.malformedErrorResponse`, carrying at most 512 B of whole UTF-8 (a character split by the cap is dropped), and nothing when the reply isn't HTTP, the origin or type failed, or the carried bytes aren't strict UTF-8 (RFC 3629, by the standard library's decoder; only a VALID start of a character the cap cut is dropped, and bytes past the cap are never read). `APIEnvelope.requirePayload()`: a 2xx that isn't a success with data is `.decode` | from the till's POSAPIClient (#2880), with the reviewer's A1-A4 on #5562 |
| `APIClientError.swift` | `APIClientError`, `APIError` (raw code). **v1.15:** `APIClientError.isCancellation(_:)` (CancellationError, NSURLErrorDomain -999, either wrapped in `.transport`) | typed code enums stay per app |
| `TrustPinning.swift` | fail-closed anchor pinning (a pinned host that isn't a valid hostname fails closed) + an optional mTLS `ClientTLSCredential` (identity + chain), pinned host only. **v1.5:** a pinned session never follows a redirect (the 3xx is the response). **v1.6:** `PinnedSessionDelegate.validatedPinnedHost(_:)` is public. **v1.7:** a refused pinned trust logs its failed checks as codes. **v1.15:** `validatedPinnedHost(_:allowIP:)` is `HostName.problem` after normalising (single labels such as `localhost` refused; an IP only with `allowIP`, canonical only, and `pinnedSession` / the delegate's init take the same `allowIP`); `pinnedSession`'s default configuration is `ephemeralConfiguration()` | decision unchanged; Logger, anchors and identity injected; redirect refusal new in v1.5 |
| `KeychainStore.swift` | `KeychainStore<Key>`, `ThisDeviceOnly` classes only. **v1.8:** an update re-applies the store's class | generic key; service id + accessibility supplied by the app |
| `PrivacyCover.swift` | **v1.9:** the App Switcher cover: a window per scene above every sheet and alert, made ahead, hidden and opaque, shown on `willDeactivate` and hidden on `didActivate`; the cover's content is the app's (`PrivacyCoverView(label:)` is a plain one). **v1.10:** it puts the keyboard away as it shows | from the POS app (#3920), unchanged but for the app-supplied content |
| `BrandTheme.swift` | **v1.11:** the SHAPE of an app's brand colours: `BrandColor(hex:)` accepts strictly `#RRGGBB`; `BrandTheme` reads Info.plist `WPBrandPrimary` / `WPBrandPrimaryDark` (absent or invalid primary → the neutral fallback, logged once without echoing the value; dark absent or invalid → the primary); on-primary text is black or white by WCAG contrast (always ≥ 4.5:1); light/dark-resolving `UIColor` and `Color` | new (BOS #5183); NO tenant values: each app's tenant file supplies them |
| `BrandAccent.swift` | **v1.12:** the brand colour as a FOREGROUND (BOS #5406, Chris's option 1): `BrandAccent.readable(_:on:target:fillAlpha:)` moves only the OKLab lightness (hue and chroma held, chroma clamped to sRGB) by a 40-step bisection, just far enough for 4.5:1 on the HARDEST of the system's 12 surfaces (6 backgrounds × base/elevated, resolved through UITraitCollection), 7:1 on Increase Contrast's; a colour that already reads is unchanged. `BrandTheme.accent(dark:high:)`, `accentUIColor`, `accentColor`. Rule: a FILL (something sits on it) keeps `primary`/`primaryDark`; anything drawn ON the app's surface uses the accent. Both apps assert one vector file | from the till (pos-app #150), byte for byte |
| `HostName.swift` | **v1.15:** `HostName.problem(_:allowIP:)`, the one strict rule for a configured host (FQDN, ≥ 2 LDH labels, last label starts with a letter, lower case, no scheme/port/path); an IP only with `allowIP` and only as a canonical dotted quad; `Problem` cases match the staff app's `MalformedReason` | from the staff app's `APIConfig.hostProblem` (mobile #130), with leading-zero octets refused |
| `BoundedImage.swift` | **v1.14:** the one bounded decode for outside pictures: the type read from the bytes and matched EXACTLY against the caller's set, the header's width × height checked (> 0, no overflow, within `maxSourcePixels`) before any decode, then only a thumbnail at `maxPixelSize` (no full-size decode exists), first frame only. ImageIO only, no UIKit | from the till's ImageGate (pos-app #4110 A.3, #141), with the till's constants as the caller's |
| `KeyedLoader.swift` | **v1.17:** `KeyedLoader<Key, Value>` (main actor): one load per key (callers join it and share its value or error; a failure isn't cached), a cancelled caller gets CancellationError at once and the last to leave cancels the load (never joined after), `remove(key)` / `removeAll()` answer every waiting caller CancellationError and cache nothing loaded before them, and each caller re-checks after its await, so a wipe that runs after the load answered still wins; an NSCache with count and cost limits (hints: it may evict any time) and a cheap `stillGood` check on every hit | from the till's TillImages (#145/#146/#158), with frontend-ios's throwing load and return-side guard and the reviewer's K1-K6 on #5563 |
| `DER.swift`, `CertificateSigningRequest.swift` | PKCS#10 for any P-256 `SecKey` (software or Secure Enclave) | generalised from the SIP key; byte-identical output |

## Testing

```bash
MAC_HOST=<the Mac's address> MAC_USER=<its SSH user> scripts/mac-test.sh
```

It runs on the Mac build host:
1. a SwiftPM build (how the apps consume it);
2. the suite **hosted** in a throwaway app under `Tests/Host`, because unhosted test bundles get
   `-34018` from every keychain call in the Simulator;
3. per-device counts from the result bundle (zero tests = failure);
4. `openssl req -verify` on a CSR signed by a real Secure Enclave key (Apple-Silicon Simulators have
   one).

Fixtures are a test-only PKI (`scripts/make-test-fixtures.sh`) and, for CSR byte-identity, a fixed
key with `openssl req`-generated golden `CertificationRequestInfo` bytes (`golden-*`). Those were
generated once and are deliberately not regenerated by the script: they pin compatibility, and
regenerating them would only prove the code agrees with itself.

## Migration notes

- **v1.5, redirects.** The softphone refused redirects whose 3xx came FROM the pinned host
  (APIPinning keys on `response.url.host`). v1.5 refuses EVERY redirect on the pinned session,
  including a 3xx from another host's response on that session. The 3xx reaches the caller as the
  response, so an API client that accepts only 2xx sees it as an error. Nothing in the softphone
  relies on a followed redirect (frontend-ios, 2026-10-22). A genuinely needed cross-host fetch
  goes on a separate unpinned, ephemeral session with no client identity, explicitly.
- **v1.6, `validatedPinnedHost(_:)` public.** Callers must use the RETURNED value (normalised:
  lower case, a trailing dot stripped), e.g. to build their API base URL, never the raw input, so the
  URL's host and the pin are the same string.
- **v1.7, refusal codes.** Each refused pinned server trust now logs ONE `.error` line on the logger
  the app passes: `pinned server trust REFUSED: result=<SecTrustResultType> error=<OSStatus>
  checks=<place>:<check> …` (e.g. `0:SSLHostname`, `1:NameConstraints`; an unlisted check name logs as
  `other`; refused before evaluation: `result=unevaluated no_anchors` / `anchor_setters=<a>,<b>`).
  The codes come from the SAME evaluation as the decision (`evaluateWithCodes`, one body;
  `evaluate` returns its decision), read only after it ran. Codes only, never the host, a
  certificate field or an error's text. No public API changes. The decision is unchanged (the same
  `.cancel`), but it's the trust gate, so v1.7 needs the reviewer's pinning re-review and the
  softphone's on-device ACCEPT/REJECT self-test
  (APIPinDiagnostic) on the rc that adopts it.
- **v1.8, keychain accessibility on update.** `KeychainStore.write` now sets the store's
  accessibility class on the UPDATE path too (BOS #4160). Before, an update kept the item's old
  class, so an item written under a weaker class by an older build stayed weaker than the store
  promised. On adopting v1.8, an app's existing items move to their store's class on their next
  write. That's a no-op wherever a store's class never changed (the POS app's two stores never
  have). An item that a background wake must read (a VoIP push, say) must stay
  `afterFirstUnlockThisDeviceOnly`: moving it to `whenUnlocked` would make it unreadable while the
  device is locked. No public API changes.
- **v1.9, `PrivacyCover`** (BOS #4160 item 4). The POS app's App Switcher cover (#3920), made
  shared so the softphone can adopt it. Call `PrivacyCover.shared.start { … }` once at launch with
  the cover's content. Each scene gets its own window at `.alert + 1`, made hidden as the scene
  connects, with an opaque `systemBackground` so the first frame is covered before SwiftUI draws.
  It's shown on `UIScene.willDeactivateNotification` (posted synchronously, before iOS takes the
  snapshot) and hidden on `didActivateNotification`. It takes touches while shown, never key focus.
  It also covers while a system sheet is up (CallKit, Apple Pay, Tap to Pay), so check what users
  see then. New public API only; nothing existing changes.
- **v1.10, the keyboard under `PrivacyCover`** (BOS #4160, Chris's App Switcher screenshot from
  the till). The system keyboard's window is drawn above any window an app makes, so a keyboard
  left up showed over the cover, with a suggestion bar that can show what was typed. Raising the
  cover's level doesn't fix it (tried at 10,000,001, iPhone and iPad). As the cover shows, editing
  now ends in the scene's other windows, without animation, so the keyboard is gone before the
  snapshot. **Behaviour change:** whenever the scene goes inactive (the App Switcher, Control
  Centre, a system alert, a full-screen call), a focused field loses focus and doesn't get it back
  when the scene returns; the user taps it again. No API changes.
- **v1.11, `BrandTheme`** (BOS #5183, agreed by frontend-pos, frontend-ios and the reviewer for
  #5170 and #4219). New public API only; nothing existing changes. An app opts in by setting
  `WPBrandPrimary` (and optionally `WPBrandPrimaryDark`) in Info.plist from its gitignored tenant
  xcconfig (`WP_BRAND_PRIMARY` / `WP_BRAND_PRIMARY_DARK`), then reading `BrandTheme.fromMainBundle(log:)`.
  The tenant values never live here or in either app's repo. A later runtime override (BOS
  settings) must be parsed with `BrandColor(hex:)` too, so it gets the same strict check. The
  AccentColor colorset and the app icon stay build-time, rendered by each app's tenant script,
  because iOS reads them before launch.
- **v1.12, `BrandAccent`** (BOS #5406; Chris's option 1 on the reviewer's contrast finding; the
  reviewer's GO on the outline). New public API only; nothing existing changes. In dark mode the
  tenant's dark value fails as text on dark surfaces (2.2–3.3:1), so a FOREGROUND (the app-wide
  tint, text, symbols, links, outlines, focus rings, status dots) uses `BrandTheme.accentUIColor`,
  and a FILL (text or a glyph on the brand colour) keeps `primary`/`primaryDark` with `onPrimary`.
  Light mode derives too, as the till does: a brand that already reads is unchanged. Ported byte for
  byte from the till's `BrandAccent`; `Tests/WoodpatchCoreTests/Fixtures/brand-accent-vectors-v1.json`
  is asserted by both apps' suites, so a change to the algorithm changes the file in the same PR.
  The AccentColor colorset is still each app's build-time asset: anything iOS draws from it before
  the app's runtime tint (launch screen, widgets, extensions, the Watch) is the app's to check.
- **v1.13, `JSONCoding`** (BOS #5481, the reviewer's efficiency audit). `decoder()` built a fresh
  `ISO8601DateFormatter` for every date field; it now shares two whose options are fixed at creation
  (fractional, then whole), so nothing mutates a shared formatter. The same class, options and order,
  so the parse is the same; `JSONCodingTests` pins it against the old path and under concurrency.
  New public `JSONCoding.date(from:)` for app code that parses a BOS timestamp by hand.
- **v1.14, `BoundedImage` and `send(_:maxBytes:)`** (BOS #5560, the reviewer's #5552 audit; Chris's
  ruling 2026-11-25: the shared library first, then mobile #150 adopts it). New public API, and ONE
  BREAKING change: `Transport` gains a second requirement, `send(_:maxBytes:)`, with no default, so
  every conformer (each app's wrappers and test doubles) must say how it caps. A default that read
  everything and checked afterwards would have let a wrapper silently lose the streaming cap, which
  is the point of it. A stub with its bytes in memory implements it as
  `(try ResponseTooLarge.check(data, maxBytes: maxBytes), response)`. `BoundedImage.thumbnail` takes
  every limit from the caller: allow only the types you show (each is a parser exposed to the
  sender), and a viewer asks for its screen's long side, never full size. **`maxSourcePixels` is
  the real memory ceiling:** ImageIO scales a JPEG as it decodes, but may decode a whole PNG or
  WebP source to make the thumbnail, so budget about 4 bytes per source pixel (the till's 40 MP is
  about 160 MB of temporary memory). An MMS viewer should pick a much smaller budget. Give a
  capped session a `timeoutIntervalForResource` too: a server can trickle bytes within the cap.
- **v1.15, small shared helpers** (BOS #5566, the reviewer's #5552 audit, items 9-12). Additive, with
  two deliberate tightenings. `HostName.problem(_:allowIP:)` is the staff app's host rule, lifted, and
  `validatedPinnedHost` is rebuilt on it, which REFUSES what v1.14 accepted: single-label names
  (`localhost`), and any IP unless the caller passes `allowIP: true` (a dev server). `pinnedSession`
  and `PinnedSessionDelegate.init` take the same `allowIP`, so a session pins exactly what the
  pre-check accepted. Pass one value to both. Every inet_aton
  alias (`127.1`, `0177.0.0.1`, `127.000.0.1`, `010.0.0.1`, `0x7f.0x1`, `2130706433`) is refused even
  then. No pinned host in either app is a single label or an IP. `pinnedSession`'s default
  `configuration` is now `ephemeralConfiguration()` (no URL cache, cookies or credential store)
  instead of `.default`. Neither app relies on the default: the till passes its own, and the staff app
  pins through its own `APIPinning` until #5567. `APIClientError.isCancellation(_:)` is lifted from
  the till. `JSONCoding`'s date decode error drops the wire value.
- **v1.16, `APIRefusal`** (BOS #5562, the reviewer's #5552 audit item 4). New public API, nothing
  changed. Both apps read a refusal by the same rules, so a captive portal's page or another host's
  reply can never end a session or wipe a credential. Rules in the file header. **A wipe stays each
  app's decision,** keyed on the CODE of an `APIError` that `decode` returned, never on a status alone
  and never on a body that failed the rules; log the code, never the body or message. The origin
  check is the SECOND line: redirects stay refused at the session delegate (v1.5). A 2xx is never a
  refusal: `decode` refuses a 2xx, and `requirePayload()` makes `success: false` or a missing `data` a `.decode` (agreed with
  frontend-ios). `ReplyOriginError.notThePinnedOrigin` replaces the till's own `notThePinnedHost`. Content-Type trims only ASCII space and tab, and `requireFromPinnedOrigin` refuses a reply that isn't HTTP, as `decode` does.
- **v1.17, `KeyedLoader`** (BOS #5563, the reviewer's #5552 audit). New public API, nothing changed.
  The single-flight memory cache the till's pictures use, for the staff app's PinnedMediaLoader
  too: it fixes the staff app's duplicate thumbnail fetches and its re-cache after a credential
  wipe. Each load is tracked by its own object, so an old load finishing late can't touch a newer
  one for the same key. Keep `stillGood` cheap: it runs on the main actor for every hit. The till
  wraps `value(for:load:)` in `try?` (any error, cancellation included, is its placeholder).
