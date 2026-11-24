// BrandAccent.swift (v1.12, BOS #5406)
// ────────────────────────────────────────────────────────────────────
// The brand colour made READABLE as a foreground on an app's own surfaces (Chris, 2026-11-24,
// option 1, after the reviewer found the tenant's dark value fails as text on dark surfaces).
//
// Two roles, one rule (it's a FILL only if something sits ON it):
// - FILL: the brand colour with text or a glyph drawn on it (a prominent button, the selected
//   key or tab, a banner, a message bubble with text). It keeps the tenant's value, with
//   `onPrimary` text: `BrandTheme.primary` / `primaryDark`.
// - FOREGROUND: anything drawn ON the app's own surface (the app-wide tint, text, an SF Symbol,
//   a link, an outline, a focus ring, a status dot). It's the ACCENT: `BrandTheme.accent…`,
//   the same hue and chroma with only its OKLab lightness moved, just far enough for 4.5:1 on
//   EVERY surface of that mode (7:1 under Increase Contrast). A tenant colour that already
//   reads comes back unchanged, so there's no second tenant value.
//
// Ported BYTE FOR BYTE from the till's BrandAccent (pos-app #150 at 389de7e, frontend-pos),
// so both apps draw the same shade; the till moves onto this copy and drops its own. Both test
// suites assert one vector file (Tests/WoodpatchCoreTests/Fixtures/brand-accent-vectors-v1.json)
// so the two can't drift (the reviewer's addition 1 on #5406). Change the algorithm here and
// the vector file changes with it, in the same PR, for both apps.
//
// The reviewer's points it pins (#5406):
// 1. Judged against the HARDEST surface: the LIGHTEST in dark mode (a light foreground's worst
//    case), the darkest in light mode. The surfaces are the system's own backgrounds, base and
//    elevated (sheets, popovers), resolved through UITraitCollection, never typed in.
// 2. Every surface in the list reaches the target, not one (the tests assert all of them).
// 3. Lightness moves in OKLab, holding hue and chroma, with chroma pulled in only as far as the
//    sRGB gamut needs. A bisection (40 steps) from the colour's own lightness towards white (or
//    black) ends in a fixed number of steps and gives the same answer whatever the start, so a
//    lighter input never gives a darker result (within 8-bit rounding).
// 4. Increase Contrast: 7:1, judged on the surfaces as the system draws them then (its dark
//    backgrounds are lighter).
//
// No tenant values here. Floating point appears only in colour maths (display, not money).

import SwiftUI
import UIKit

public enum BrandAccent {
    /// WCAG 1.4.3 for text (which also covers 1.4.11's 3:1 for components).
    public static let minimumContrast = 4.5
    /// Under Increase Contrast (WCAG 1.4.6).
    public static let increasedContrast = 7.0

    /// `color` at `alpha` over `surface`, as the system composites a fill (gamma-encoded sRGB,
    /// as iOS blends; the till measured it on a rendered pixel).
    public static func composite(
        _ color: BrandColor,
        alpha: Double,
        over surface: BrandColor
    ) -> BrandColor {
        func mix(_ top: UInt8, _ bottom: UInt8) -> UInt8 {
            UInt8((alpha * Double(top) + (1 - alpha) * Double(bottom)).rounded())
        }
        return BrandColor(
            red: mix(color.red, surface.red),
            green: mix(color.green, surface.green),
            blue: mix(color.blue, surface.blue)
        )
    }

    /// The app's surfaces in one appearance, as the system draws them: the six system
    /// backgrounds, base and elevated, under Increase Contrast when `high`.
    public static func surfaces(dark: Bool, high: Bool = false) -> [BrandColor] {
        let colors: [UIColor] = [
            .systemBackground, .secondarySystemBackground, .tertiarySystemBackground,
            .systemGroupedBackground, .secondarySystemGroupedBackground,
            .tertiarySystemGroupedBackground,
        ]
        let levels: [UIUserInterfaceLevel] = [.base, .elevated]
        return colors.flatMap { color in
            levels.map { level in
                brand(color.resolvedColor(with: UITraitCollection(traitsFrom: [
                    UITraitCollection(userInterfaceStyle: dark ? .dark : .light),
                    UITraitCollection(userInterfaceLevel: level),
                    UITraitCollection(accessibilityContrast: high ? .high : .normal),
                ])))
            }
        }
    }

    /// The surface that's hardest to read on: the lightest in dark mode, the darkest in light.
    public static func hardest(dark: Bool, high: Bool = false) -> BrandColor {
        let all = surfaces(dark: dark, high: high)
        return (dark
            ? all.max { $0.relativeLuminance < $1.relativeLuminance }
            : all.min { $0.relativeLuminance < $1.relativeLuminance })!
    }

    /// A resolved system colour as a BrandColor (sRGB, rounded).
    public static func brand(_ color: UIColor) -> BrandColor {
        var red: CGFloat = 0, green: CGFloat = 0, blue: CGFloat = 0, alpha: CGFloat = 0
        color.getRed(&red, green: &green, blue: &blue, alpha: &alpha)
        func byte(_ value: CGFloat) -> UInt8 { UInt8((min(1, max(0, value)) * 255).rounded()) }
        return BrandColor(red: byte(red), green: byte(green), blue: byte(blue))
    }

    /// `color` moved just far enough in OKLab lightness to reach `target` on `surface` (lighter
    /// on a dark one, darker on a light one). `fillAlpha`: the colour is also drawn as its own
    /// fill at that opacity behind it (a bordered button's label), and must read on that too.
    /// The far end (white, or black) comes back when even it doesn't reach the target.
    public static func readable(
        _ color: BrandColor,
        on surface: BrandColor,
        target: Double = minimumContrast,
        fillAlpha: Double = 0
    ) -> BrandColor {
        func reads(_ candidate: BrandColor) -> Bool {
            candidate.contrastRatio(with: surface) >= target
                && (fillAlpha == 0
                    || candidate.contrastRatio(
                        with: composite(candidate, alpha: fillAlpha, over: surface)
                    ) >= target)
        }
        guard !reads(color) else { return color }
        let lighten = surface.relativeLuminance < 0.18
        let start = OKLab(color)
        func at(_ lightness: Double) -> BrandColor {
            OKLab(l: lightness, a: start.a, b: start.b).inGamut
        }
        func passes(_ lightness: Double) -> Bool { reads(at(lightness)) }
        // The far end (white, or black) is the last resort.
        let end: Double = lighten ? 1 : 0
        guard passes(end) else { return lighten ? .white : .black }
        // Bisection for the nearest lightness that passes: the same answer whatever the start,
        // so a lighter input never gives a darker accent, and it ends in a fixed number of steps.
        var fails = start.l, holds = end
        for _ in 0 ..< 40 {
            let mid = (fails + holds) / 2
            if passes(mid) { holds = mid } else { fails = mid }
        }
        return at(holds)
    }

    /// OKLab (Björn Ottosson, 2020), from and to sRGB.
    public struct OKLab: Equatable, Sendable {
        public var l: Double, a: Double, b: Double

        public init(l: Double, a: Double, b: Double) {
            self.l = l
            self.a = a
            self.b = b
        }

        public init(_ color: BrandColor) {
            func linear(_ byte: UInt8) -> Double {
                let c = Double(byte) / 255
                return c <= 0.04045 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4)
            }
            let r = linear(color.red), g = linear(color.green), bl = linear(color.blue)
            let lms = [
                0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * bl,
                0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * bl,
                0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * bl,
            ].map { cbrt($0) }
            l = 0.2104542553 * lms[0] + 0.7936177850 * lms[1] - 0.0040720468 * lms[2]
            a = 1.9779984951 * lms[0] - 2.4285922050 * lms[1] + 0.4505937099 * lms[2]
            b = 0.0259040371 * lms[0] + 0.7827717662 * lms[1] - 0.8086757660 * lms[2]
        }

        /// Linear sRGB, unclamped (out of gamut when a channel leaves 0...1).
        public var linearRGB: (Double, Double, Double) {
            let l_ = l + 0.3963377774 * a + 0.2158037573 * b
            let m_ = l - 0.1055613458 * a - 0.0638541728 * b
            let s_ = l - 0.0894841775 * a - 1.2914855480 * b
            let (L, M, S) = (l_ * l_ * l_, m_ * m_ * m_, s_ * s_ * s_)
            return (
                4.0767416621 * L - 3.3077115913 * M + 0.2309699292 * S,
                -1.2684380046 * L + 2.6097574011 * M - 0.3413193965 * S,
                -0.0041960863 * L - 0.7034186147 * M + 1.7076147010 * S
            )
        }

        /// This colour in sRGB, its chroma (a, b) pulled in only as far as the gamut needs,
        /// hue and lightness held.
        public var inGamut: BrandColor {
            func fits(_ lab: OKLab) -> Bool {
                let (r, g, b) = lab.linearRGB
                return [r, g, b].allSatisfy { $0 >= -0.0001 && $0 <= 1.0001 }
            }
            var low = 0.0, high = 1.0
            if fits(self) { return srgb(self) }
            for _ in 0 ..< 30 {
                let mid = (low + high) / 2
                if fits(OKLab(l: l, a: a * mid, b: b * mid)) { low = mid } else { high = mid }
            }
            return srgb(OKLab(l: l, a: a * low, b: b * low))
        }

        private func srgb(_ lab: OKLab) -> BrandColor {
            func byte(_ linear: Double) -> UInt8 {
                let c = min(1, max(0, linear))
                let encoded = c <= 0.0031308 ? 12.92 * c : 1.055 * pow(c, 1 / 2.4) - 0.055
                return UInt8((min(1, max(0, encoded)) * 255).rounded())
            }
            let (r, g, b) = lab.linearRGB
            return BrandColor(red: byte(r), green: byte(g), blue: byte(b))
        }

        /// Hue angle in radians.
        public var hue: Double { atan2(b, a) }
        public var chroma: Double { (a * a + b * b).squareRoot() }
    }
}

// MARK: - The theme's accent

extension BrandTheme {
    /// The accent (FOREGROUND) colour for one appearance: the light primary judged on the
    /// hardest light surface, the dark primary on the hardest dark one, at 7:1 on Increase
    /// Contrast's own surfaces when `high`. Light mode derives too, as the till does: a brand
    /// that already reads at 4.5:1 on the darkest light surface comes back unchanged, and only
    /// a pale one darkens.
    public func accent(dark: Bool, high: Bool = false) -> BrandColor {
        BrandAccent.readable(
            dark ? primaryDark : primary,
            on: BrandAccent.hardest(dark: dark, high: high),
            target: high ? BrandAccent.increasedContrast : BrandAccent.minimumContrast
        )
    }

    /// The accent as a UIColor that resolves per trait (style × Increase Contrast). The four
    /// values are worked out once, when this is read: build it once per launch and keep it.
    public var accentUIColor: UIColor {
        let light = accent(dark: false).uiColor, dark = accent(dark: true).uiColor
        let lightHigh = accent(dark: false, high: true).uiColor
        let darkHigh = accent(dark: true, high: true).uiColor
        return UIColor { traits in
            let high = traits.accessibilityContrast == .high
            return traits.userInterfaceStyle == .dark
                ? (high ? darkHigh : dark)
                : (high ? lightHigh : light)
        }
    }

    /// SwiftUI equivalent (it follows the colour scheme and Increase Contrast).
    public var accentColor: Color { Color(uiColor: accentUIColor) }
}
