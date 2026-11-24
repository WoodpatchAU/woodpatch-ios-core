// BrandAccentTests.swift (v1.12, BOS #5406)
// The brand colour as a FOREGROUND on an app's own surfaces (Chris, 2026-11-24, option 1, and
// the reviewer's points): the same hue and chroma (OKLab), only the lightness moved, just far
// enough for 4.5:1 on EVERY surface of that mode, base and elevated, and 7:1 on Increase
// Contrast's own surfaces. Ported from the till's BrandAccentTests (pos-app #150 at 389de7e),
// plus the shared vector file both apps assert, and the theme's resolved accent.
// The colours here are samples, never a tenant's; built from data, never typed as components.

import Foundation
import Testing
import UIKit
@testable import WoodpatchCore

private func colour(_ hex: String) -> BrandColor { BrandColor(hex: hex)! }

@Suite struct BrandAccentTests {

    private var darkSurface: BrandColor { BrandAccent.hardest(dark: true) }
    private var lightSurface: BrandColor { BrandAccent.hardest(dark: false) }

    // MARK: - The surfaces

    /// The hardest surface is the LIGHTEST dark one (a light foreground's worst case), elevated
    /// sheets included: never black, which would pass trivially.
    @Test func theSurfacesAreTheSystemsOwnAndTheHardestIsTheLightestDarkOne() {
        let dark = BrandAccent.surfaces(dark: true)
        #expect(dark.count == 12, "six backgrounds, base and elevated")
        #expect(dark.allSatisfy { $0.relativeLuminance <= darkSurface.relativeLuminance })
        #expect(darkSurface.relativeLuminance > 0.03, "an elevated surface, not #000 or #2C2C2E")
        #expect(BrandAccent.surfaces(dark: false).allSatisfy {
            $0.relativeLuminance >= lightSurface.relativeLuminance
        })
        // Under Increase Contrast the dark surfaces are lighter: 7:1 is judged on those.
        let highDark = BrandAccent.hardest(dark: true, high: true)
        #expect(highDark.relativeLuminance >= darkSurface.relativeLuminance)
        #expect(BrandAccent.surfaces(dark: true, high: true).allSatisfy {
            $0.relativeLuminance <= highDark.relativeLuminance
        })
    }

    // MARK: - The algorithm

    /// Every colour a tenant could set (a 6×6×6 sample of the cube) reads at the target on
    /// EVERY surface, in both modes: 4.5:1 on the usual surfaces, 7:1 on Increase Contrast's.
    @Test(arguments: [
        (BrandAccent.minimumContrast, false), (BrandAccent.increasedContrast, true),
    ])
    func anyBrandColourBecomesReadableOnEverySurface(target: Double, high: Bool) {
        let steps: [UInt8] = [0, 51, 102, 153, 204, 255]
        let dark = BrandAccent.surfaces(dark: true, high: high)
        let light = BrandAccent.surfaces(dark: false, high: high)
        let hardDark = BrandAccent.hardest(dark: true, high: high)
        let hardLight = BrandAccent.hardest(dark: false, high: high)
        for r in steps { for g in steps { for b in steps {
            let brand = BrandColor(red: r, green: g, blue: b)
            let onDark = BrandAccent.readable(brand, on: hardDark, target: target)
            let onLight = BrandAccent.readable(brand, on: hardLight, target: target)
            #expect(dark.allSatisfy { onDark.contrastRatio(with: $0) >= target },
                    "\(brand.hex) dark → \(onDark.hex)")
            #expect(light.allSatisfy { onLight.contrastRatio(with: $0) >= target },
                    "\(brand.hex) light → \(onLight.hex)")
        } } }
    }

    /// The OKLab hue holds, the lightness only rises, and only as far as needed (one step less
    /// wouldn't reach it).
    @Test(arguments: ["#1A5E63", "#0F4C5C", "#3B1F5C", "#7F0000", "#5A5A5A", "#0000FF"])
    func onlyTheLightnessMovesAndOnlyAsFarAsNeeded(_ hex: String) {
        let brand = colour(hex)
        let surface = darkSurface
        #expect(brand.contrastRatio(with: surface) < 4.5, "a sample that needs it")
        let accent = BrandAccent.readable(brand, on: surface)
        let before = BrandAccent.OKLab(brand), after = BrandAccent.OKLab(accent)
        #expect(after.l > before.l)
        if before.chroma > 0.02, after.chroma > 0.02 {
            let drift = abs(atan2(sin(after.hue - before.hue), cos(after.hue - before.hue)))
            #expect(drift < 0.06, "\(hex): the hue moved to \(accent.hex)")
        }
        let lessLight = BrandAccent.OKLab(l: after.l - 0.01, a: before.a, b: before.b).inGamut
        #expect(lessLight.contrastRatio(with: surface) < 4.5,
                "\(hex): \(accent.hex) is lighter than it needs to be")
    }

    @Test(arguments: [("#9FE3D9", true), ("#FFC107", true), ("#003040", false), ("#5B2C83", false)])
    func aColourThatAlreadyReadsIsUnchanged(_ hex: String, _ onDark: Bool) {
        let brand = colour(hex)
        let surface = onDark ? darkSurface : lightSurface
        #expect(brand.contrastRatio(with: surface) >= 4.5)
        #expect(BrandAccent.readable(brand, on: surface) == brand)
    }

    /// Monotonic: a lighter input never gives a darker accent, and a higher target never gives
    /// a lower-contrast one.
    @Test func itIsMonotonic() {
        let ramp = stride(from: 0, through: 200, by: 8).map {
            BrandColor(red: UInt8($0), green: UInt8($0), blue: UInt8($0))
        }
        let out = ramp.map { BrandAccent.readable($0, on: darkSurface).relativeLuminance }
        // Within the result's own 8-bit rounding (one grey step is about 0.005 of luminance):
        // pure black has exactly zero chroma, its neighbours a tiny one, so they can land one
        // byte apart.
        #expect(zip(out, out.dropFirst()).allSatisfy { $0 <= $1 + 0.005 }, "\(out)")
        #expect(out.last! > out.first!, "and it does rise once the input itself reads")
        for hex in ["#1A5E63", "#7F0000", "#0000FF"] {
            let normal = BrandAccent.readable(colour(hex), on: darkSurface)
            let high = BrandAccent.readable(colour(hex), on: darkSurface,
                                            target: BrandAccent.increasedContrast)
            #expect(high.contrastRatio(with: darkSurface) >= normal.contrastRatio(with: darkSurface))
        }
    }

    /// It always ends: the extremes and an impossible target come back.
    @Test func itAlwaysEnds() {
        #expect(BrandAccent.readable(.black, on: darkSurface).contrastRatio(with: darkSurface) >= 4.5)
        #expect(BrandAccent.readable(.white, on: lightSurface).contrastRatio(with: lightSurface) >= 4.5)
        #expect(BrandAccent.readable(colour("#336699"), on: darkSurface, target: 50) == .white,
                "past white: white")
    }

    @Test func aLightBrandDarkensOnALightSurface() {
        let brand = colour("#7FD4C8")
        let accent = BrandAccent.readable(brand, on: lightSurface)
        #expect(accent.contrastRatio(with: .white) >= 4.5)
        #expect(BrandAccent.OKLab(accent).l < BrandAccent.OKLab(brand).l)
    }

    @Test func aFillAlphaJudgesTheLabelOnItsOwnFillToo() {
        let brand = colour("#1A5E63")
        let plain = BrandAccent.readable(brand, on: darkSurface)
        let bordered = BrandAccent.readable(brand, on: darkSurface, fillAlpha: 0.25)
        let fill = BrandAccent.composite(bordered, alpha: 0.25, over: darkSurface)
        #expect(bordered.contrastRatio(with: fill) >= 4.5 || bordered == .white)
        #expect(BrandAccent.OKLab(bordered).l >= BrandAccent.OKLab(plain).l)
    }

    @Test func okLabRoundTrips() {
        for hex in ["#1A5E63", "#7F0000", "#FFC107", "#5A5A5A", "#000000", "#FFFFFF", "#0000FF"] {
            let back = BrandAccent.OKLab(colour(hex)).inGamut, orig = colour(hex)
            #expect(abs(Int(back.red) - Int(orig.red)) <= 1
                && abs(Int(back.green) - Int(orig.green)) <= 1
                && abs(Int(back.blue) - Int(orig.blue)) <= 1, "\(hex) → \(back.hex)")
        }
    }

    // MARK: - One algorithm for both apps: the shared vector file

    private struct VectorFile: Decodable {
        struct Surfaces: Decodable { let dark, darkHigh, light, lightHigh: String }
        struct FillAlpha: Decodable { let dark, light: Double }
        struct Vector: Decodable {
            let input, dark, darkHigh, light, lightHigh: String
            // A bordered button's label on its own translucent fill (fillAlpha), the till's
            // borderedTint: 4.5:1 normally, 7:1 on Increase Contrast's surfaces.
            let borderedDark, borderedDarkHigh, borderedLight, borderedLightHigh: String
        }
        let version: Int
        let generator: String
        let surfaces: Surfaces
        let fillAlpha: FillAlpha
        let vectors: [Vector]
    }

    private func vectorFile() throws -> VectorFile {
        let data = try Data(contentsOf: Fixtures.url("brand-accent-vectors-v1", "json"))
        return try JSONDecoder().decode(VectorFile.self, from: data)
    }

    /// The vectors were worked out on these surfaces. If iOS changes its backgrounds, this
    /// fails first, and the file is regenerated for BOTH apps in one PR.
    @Test func theVectorFilesSurfacesAreTheSystemsOwn() throws {
        let file = try vectorFile()
        #expect(file.version == 1)
        #expect(file.generator.hasPrefix("pos-app "), "generated from the till's code, at a commit")
        #expect(BrandAccent.hardest(dark: true).hex == file.surfaces.dark)
        #expect(BrandAccent.hardest(dark: true, high: true).hex == file.surfaces.darkHigh)
        #expect(BrandAccent.hardest(dark: false).hex == file.surfaces.light)
        #expect(BrandAccent.hardest(dark: false, high: true).hex == file.surfaces.lightHigh)
    }

    /// Every vector, byte for byte, against the file's own surfaces (so a surface change shows
    /// up in the test above, not as a wall of failures here).
    @Test func everyVectorMatchesByteForByte() throws {
        let file = try vectorFile()
        #expect(file.vectors.count >= 216, "the 6×6×6 cube at least")
        let s = file.surfaces
        let a = file.fillAlpha
        let normal = BrandAccent.minimumContrast, raised = BrandAccent.increasedContrast
        let cases: [(KeyPath<VectorFile.Vector, String>, String, Double, Double)] = [
            (\.dark, s.dark, normal, 0), (\.darkHigh, s.darkHigh, raised, 0),
            (\.light, s.light, normal, 0), (\.lightHigh, s.lightHigh, raised, 0),
            (\.borderedDark, s.dark, normal, a.dark), (\.borderedDarkHigh, s.darkHigh, raised, a.dark),
            (\.borderedLight, s.light, normal, a.light),
            (\.borderedLightHigh, s.lightHigh, raised, a.light),
        ]
        for vector in file.vectors {
            for (expected, surface, target, alpha) in cases {
                let got = BrandAccent.readable(colour(vector.input), on: colour(surface),
                                               target: target, fillAlpha: alpha)
                #expect(got.hex == vector[keyPath: expected],
                        "\(vector.input) on \(surface) at \(target), fill \(alpha)")
            }
        }
    }

    // MARK: - The theme's accent

    private func resolved(_ color: UIColor, dark: Bool, high: Bool) -> BrandColor {
        BrandAccent.brand(color.resolvedColor(with: UITraitCollection(traitsFrom: [
            UITraitCollection(userInterfaceStyle: dark ? .dark : .light),
            UITraitCollection(accessibilityContrast: high ? .high : .normal),
        ])))
    }

    /// A theme whose dark value fails as text on dark surfaces (as the tenant's did): its
    /// accent reads in every mode, and the FILL keeps the value as it is.
    @Test func theThemesAccentReadsInEveryModeAndTheFillIsUnchanged() {
        let theme = BrandTheme(primary: colour("#1A5E63"), primaryDark: colour("#0F4C5C"))
        let accent = theme.accentUIColor
        for dark in [false, true] {
            for high in [false, true] {
                let target = high ? BrandAccent.increasedContrast : BrandAccent.minimumContrast
                let got = resolved(accent, dark: dark, high: high)
                #expect(got == theme.accent(dark: dark, high: high))
                #expect(BrandAccent.surfaces(dark: dark, high: high).allSatisfy {
                    got.contrastRatio(with: $0) >= target
                }, "dark \(dark) high \(high) → \(got.hex)")
            }
        }
        #expect(resolved(theme.primaryUIColor, dark: true, high: false) == colour("#0F4C5C"),
                "the fill keeps the tenant's value")
        #expect(theme.accent(dark: true) != theme.primaryDark, "this sample needed lightening")
    }

    @Test func aThemeThatAlreadyReadsKeepsItsColoursAsTheAccent() {
        let theme = BrandTheme(primary: colour("#003040"), primaryDark: colour("#9FE3D9"))
        #expect(theme.accent(dark: false) == theme.primary)
        #expect(theme.accent(dark: true) == theme.primaryDark)
    }

    @Test func theNeutralFallbackHasAReadableAccentToo() {
        for dark in [false, true] {
            for high in [false, true] {
                let target = high ? BrandAccent.increasedContrast : BrandAccent.minimumContrast
                let got = BrandTheme.neutral.accent(dark: dark, high: high)
                #expect(BrandAccent.surfaces(dark: dark, high: high).allSatisfy {
                    got.contrastRatio(with: $0) >= target
                })
            }
        }
    }
}
