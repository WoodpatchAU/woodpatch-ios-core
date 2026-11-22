// BrandThemeTests.swift (v1.11, BOS #5183)
// The shared brand-colour shape: strict #RRGGBB or the neutral fallback (logged once, never
// echoing the bad value), the dark variant's own fallback, and on-primary text chosen by
// WCAG contrast. Colours here are arbitrary test values, never a tenant's.

import Testing
import UIKit
@testable import WoodpatchCore

@Suite struct BrandThemeTests {

    // MARK: - Strict #RRGGBB

    @Test func acceptsExactlyHashAndSixHexDigitsInEitherCase() {
        #expect(BrandColor(hex: "#336699") == BrandColor(red: 0x33, green: 0x66, blue: 0x99))
        #expect(BrandColor(hex: "#a1B2c3") == BrandColor(red: 0xA1, green: 0xB2, blue: 0xC3))
        #expect(BrandColor(hex: "#a1B2c3")?.hex == "#A1B2C3")
    }

    @Test(arguments: ["", "#", "#abc", "#12345", "#1234567", "#123456FF", "123456", "0x123456",
                      " #123456", "#123456 ", "#123456\n", "#12345G", "#ＡＢＣＤＥＦ", "##12345",
                      "#-12345", "red", "javascript:alert(1)"])
    func refusesAnythingElse(_ text: String) {
        #expect(BrandColor(hex: text) == nil)
    }

    // MARK: - On-primary by contrast

    @Test func midToneAccentGetsTheHigherContrastTextNotAGuess() {
        // #777777 looks "darkish", but white on it is only ~4.48:1 (fails AA) while black is
        // ~4.68:1. A light/dark guess would pick white; the contrast rule picks black.
        let grey = BrandColor(red: 0x77, green: 0x77, blue: 0x77)
        #expect(grey.contrastRatio(with: .white) < 4.5)
        #expect(grey.onColor == .black)
        #expect(grey.contrastRatio(with: grey.onColor) >= 4.5)
    }

    @Test func darkAndLightAccentsGetTheObviousText() {
        #expect(BrandColor(red: 0x33, green: 0x66, blue: 0x99).onColor == .white)
        #expect(BrandColor(red: 0xFF, green: 0xFF, blue: 0x00).onColor == .black)
    }

    @Test func everyGreyMeetsAA() {
        // The worst case for black-or-white text is a mid grey; sweep them all.
        for v in 0...255 {
            let c = BrandColor(red: UInt8(v), green: UInt8(v), blue: UInt8(v))
            #expect(c.contrastRatio(with: c.onColor) >= 4.5, "grey \(c.hex)")
        }
    }

    @Test func contrastMatchesTheWCAGEndpoints() {
        #expect(abs(BrandColor.black.contrastRatio(with: .white) - 21) < 0.001)
        #expect(abs(BrandColor.white.contrastRatio(with: .white) - 1) < 0.001)
    }

    // MARK: - Reading Info.plist

    @Test func validPrimaryAndDarkAreUsedWithNoLog() {
        var lines: [String] = []
        let theme = BrandTheme(infoDictionary: [BrandTheme.primaryKey: "#336699",
                                                BrandTheme.primaryDarkKey: "#6699CC"],
                               log: { lines.append($0) })
        #expect(theme.primary.hex == "#336699")
        #expect(theme.primaryDark.hex == "#6699CC")
        #expect(!theme.isFallback)
        #expect(lines.isEmpty)
    }

    @Test func absentDarkUsesPrimarySilently() {
        var lines: [String] = []
        let theme = BrandTheme(infoDictionary: [BrandTheme.primaryKey: "#336699"], log: { lines.append($0) })
        #expect(theme.primaryDark == theme.primary)
        #expect(lines.isEmpty)
    }

    @Test func invalidDarkUsesPrimaryAndLogsOnce() {
        var lines: [String] = []
        let theme = BrandTheme(infoDictionary: [BrandTheme.primaryKey: "#336699",
                                                BrandTheme.primaryDarkKey: "#zzzzzz"],
                               log: { lines.append($0) })
        #expect(theme.primaryDark == theme.primary)
        #expect(!theme.isFallback)
        #expect(lines.count == 1)
    }

    @Test func absentPrimaryIsTheNeutralFallbackLoggedOnce() {
        var lines: [String] = []
        let theme = BrandTheme(infoDictionary: [:], log: { lines.append($0) })
        #expect(theme == .neutral)
        #expect(theme.isFallback)
        #expect(lines.count == 1)
        #expect(BrandTheme(infoDictionary: nil) == .neutral)
    }

    @Test(arguments: ["javascript:alert(1)", "#33669", "336699", "$(WP_BRAND_PRIMARY)"])
    func invalidPrimaryIsTheFallbackAndTheLogNeverEchoesTheValue(_ bad: String) {
        var lines: [String] = []
        let theme = BrandTheme(infoDictionary: [BrandTheme.primaryKey: bad,
                                                BrandTheme.primaryDarkKey: "#6699CC"],
                               log: { lines.append($0) })
        #expect(theme == .neutral, "a valid dark never rescues an invalid primary")
        #expect(lines.count == 1)
        #expect(!(lines.first ?? "").contains(bad))
    }

    @Test func aNonStringValueIsInvalid() {
        var lines: [String] = []
        let theme = BrandTheme(infoDictionary: [BrandTheme.primaryKey: 0x336699], log: { lines.append($0) })
        #expect(theme == .neutral)
        #expect(lines.count == 1)
    }

    // MARK: - Light/dark resolution

    @Test func dynamicColoursFollowTheInterfaceStyle() {
        let theme = BrandTheme(infoDictionary: [BrandTheme.primaryKey: "#336699",
                                                BrandTheme.primaryDarkKey: "#FFFF00"])
        let light = theme.primaryUIColor.resolvedColor(with: UITraitCollection(userInterfaceStyle: .light))
        let dark = theme.primaryUIColor.resolvedColor(with: UITraitCollection(userInterfaceStyle: .dark))
        #expect(light == BrandColor(red: 0x33, green: 0x66, blue: 0x99).uiColor)
        #expect(dark == BrandColor(red: 0xFF, green: 0xFF, blue: 0x00).uiColor)
        let onDark = theme.onPrimaryUIColor.resolvedColor(with: UITraitCollection(userInterfaceStyle: .dark))
        #expect(onDark == BrandColor.black.uiColor, "yellow in dark mode takes black text")
    }
}
