// BrandTheme.swift (v1.11, BOS #5183)
// ────────────────────────────────────────────────────────────────────
// The SHAPE of an app's brand colours, shared by the softphone and the POS so both read the
// same keys the same way. It holds NO tenant values: the colours come from each app's
// gitignored tenant file, through its xcconfig, into Info.plist
// (WP_BRAND_PRIMARY / WP_BRAND_PRIMARY_DARK → WPBrandPrimary / WPBrandPrimaryDark).
//
// The reviewer's conditions (#5183):
// 1. No tenant values here. The neutral fallback is the only colour this file knows.
// 2. Strict validation: exactly "#RRGGBB" (as frontend-staff's safeHexColor). Anything else
//    is the neutral fallback, reported once through the app's log. A later runtime override
//    (BOS settings) must go through `BrandColor(hex:)` too.
// 3. On-primary text is chosen by WCAG 2.x contrast ratio, never by a light/dark guess.
//
// Floating point appears only in the luminance maths (display, not money).

import SwiftUI
import UIKit

/// An sRGB colour that passed the strict `#RRGGBB` check. The only way to make one from text.
public struct BrandColor: Equatable, Hashable, Sendable {
    public let red: UInt8
    public let green: UInt8
    public let blue: UInt8

    public init(red: UInt8, green: UInt8, blue: UInt8) {
        self.red = red
        self.green = green
        self.blue = blue
    }

    /// Strictly `#RRGGBB`: a leading `#`, then exactly six hex digits (either case). No
    /// whitespace, no `#RGB` shorthand, no alpha, no `0x`, no names. Anything else is nil.
    public init?(hex: String) {
        let bytes = Array(hex.utf8)
        guard bytes.count == 7, bytes[0] == UInt8(ascii: "#") else { return nil }
        var values: [UInt8] = []
        values.reserveCapacity(6)
        for byte in bytes[1...] {
            guard let nibble = Self.nibble(byte) else { return nil }
            values.append(nibble)
        }
        red = values[0] << 4 | values[1]
        green = values[2] << 4 | values[3]
        blue = values[4] << 4 | values[5]
    }

    private static func nibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
        default: return nil
        }
    }

    /// `#RRGGBB`, upper case: what a log line or a test compares.
    public var hex: String {
        let digits = Array("0123456789ABCDEF")
        return "#" + [red, green, blue].map { "\(digits[Int($0 >> 4)])\(digits[Int($0 & 0x0F)])" }.joined()
    }

    public static let black = BrandColor(red: 0, green: 0, blue: 0)
    public static let white = BrandColor(red: 255, green: 255, blue: 255)

    /// WCAG 2.x relative luminance.
    public var relativeLuminance: Double {
        func channel(_ value: UInt8) -> Double {
            let c = Double(value) / 255
            return c <= 0.03928 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)
    }

    /// WCAG 2.x contrast ratio between two colours, 1…21.
    public func contrastRatio(with other: BrandColor) -> Double {
        let a = relativeLuminance, b = other.relativeLuminance
        return (max(a, b) + 0.05) / (min(a, b) + 0.05)
    }

    /// The text colour to put ON this colour: black or white, whichever contrasts more.
    /// One of them always reaches at least 4.58:1 (the worst case is a background of
    /// luminance ~0.18), so this always meets WCAG AA's 4.5:1 for body text.
    public var onColor: BrandColor {
        contrastRatio(with: .black) >= contrastRatio(with: .white) ? .black : .white
    }

    public var uiColor: UIColor {
        UIColor(red: CGFloat(red) / 255, green: CGFloat(green) / 255, blue: CGFloat(blue) / 255, alpha: 1)
    }
}

/// An app's brand colours, read from Info.plist. Small on purpose: primary, its dark-mode
/// variant, and the text colour for each. More roles can be added when an app needs them.
///
/// `primary` / `primaryDark` are FILLS (text or a glyph sits on them, in `onPrimary`). Anything
/// drawn ON the app's own surface (the tint, text, symbols, outlines, dots) is the ACCENT:
/// `accentUIColor` / `accentColor` (v1.12, BrandAccent.swift, BOS #5406).
public struct BrandTheme: Equatable, Sendable {

    /// The Info.plist keys both apps use. Their xcconfig maps the tenant file's
    /// WP_BRAND_PRIMARY / WP_BRAND_PRIMARY_DARK into them.
    public static let primaryKey = "WPBrandPrimary"
    public static let primaryDarkKey = "WPBrandPrimaryDark"

    /// The neutral fallback: a mid grey and a lighter grey for dark mode. Not a brand.
    public static let neutral = BrandTheme(primary: BrandColor(red: 0x5A, green: 0x5A, blue: 0x5A),
                                      primaryDark: BrandColor(red: 0x9A, green: 0x9A, blue: 0x9A),
                                      isFallback: true)

    public let primary: BrandColor
    public let primaryDark: BrandColor
    /// True when the primary came from the neutral fallback (absent or invalid).
    public let isFallback: Bool

    public var onPrimary: BrandColor { primary.onColor }
    public var onPrimaryDark: BrandColor { primaryDark.onColor }

    public init(primary: BrandColor, primaryDark: BrandColor, isFallback: Bool = false) {
        self.primary = primary
        self.primaryDark = primaryDark
        self.isFallback = isFallback
    }

    /// Reads the two keys from an Info.plist dictionary.
    /// - Primary absent or invalid: the whole neutral fallback.
    /// - Dark absent: the primary is used in dark mode too. Dark invalid: likewise.
    /// Each problem is reported through `log` once PER CONSTRUCTION, with the key named and
    /// the offending value left out: a log line never repeats an unvalidated config string.
    /// Build the theme once (at launch, e.g. with `fromMainBundle`) and keep it, so a bad
    /// value is logged once per launch, not once per screen.
    public init(infoDictionary: [String: Any]?, log: (String) -> Void = { _ in }) {
        let rawPrimary = infoDictionary?[Self.primaryKey]
        guard let primaryText = rawPrimary as? String, let primary = BrandColor(hex: primaryText) else {
            log(rawPrimary == nil
                ? "theme: \(Self.primaryKey) not set; using the neutral fallback"
                : "theme: \(Self.primaryKey) is not #RRGGBB; using the neutral fallback")
            self = .neutral
            return
        }
        let rawDark = infoDictionary?[Self.primaryDarkKey]
        var dark = primary
        if let rawDark {
            if let darkText = rawDark as? String, let parsed = BrandColor(hex: darkText) {
                dark = parsed
            } else {
                log("theme: \(Self.primaryDarkKey) is not #RRGGBB; using \(Self.primaryKey) in dark mode")
            }
        }
        self.init(primary: primary, primaryDark: dark)
    }

    /// The app's theme from its main bundle.
    public static func fromMainBundle(log: (String) -> Void = { _ in }) -> BrandTheme {
        BrandTheme(infoDictionary: Bundle.main.infoDictionary, log: log)
    }

    /// Light/dark-resolving UIColors.
    public var primaryUIColor: UIColor { Self.dynamic(primary, primaryDark) }
    public var onPrimaryUIColor: UIColor { Self.dynamic(onPrimary, onPrimaryDark) }

    /// SwiftUI equivalents (they follow the colour scheme too).
    public var primaryColor: Color { Color(uiColor: primaryUIColor) }
    public var onPrimaryColor: Color { Color(uiColor: onPrimaryUIColor) }

    private static func dynamic(_ light: BrandColor, _ dark: BrandColor) -> UIColor {
        let lightColor = light.uiColor, darkColor = dark.uiColor
        return UIColor { traits in traits.userInterfaceStyle == .dark ? darkColor : lightColor }
    }
}
