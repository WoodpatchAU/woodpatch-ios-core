// BoundedImage.swift (v1.14, BOS #5560)
// ────────────────────────────────────────────────────────────────────
// The one way a picture that came from outside an app gets decoded: a product photo on the
// till, an MMS in the staff app, a logo. Lifted from the till's ImageGate (pos-app, #4110 A.3,
// the reviewer's rules of 2026-11-22 and the MUST on #141), where it has guarded every grid
// picture since. The rules:
//
// - The TYPE is read from the bytes (ImageIO's own sniff), never from Content-Type or a file
//   name, and must be one the caller allows. Each type is a parser exposed to whoever sent the
//   bytes, so allow only what you show: the till allows JPEG, PNG and WebP (VAULT's renditions);
//   HEIC and GIF are the caller's decision, never a default here.
// - The SOURCE size is checked from the header before anything is decoded: width × height must
//   be real (both > 0), must not overflow, and must be within `maxSourcePixels`. A forged
//   header claiming 100k × 100k is refused unread.
// - Only a THUMBNAIL is ever decoded, at most `maxPixelSize` on its long side
//   (CreateThumbnailFromImageAlways, so an embedded thumbnail is never trusted; with the EXIF
//   orientation applied; ShouldCacheImmediately, so the decode happens here, off whatever thread
//   the caller chose, not later at draw time on main). There is no "full size": a viewer asks
//   for its screen's long side (about 4096 px), never nil.
// - Only the first image of the file (an animated GIF shows its first frame).
//
// ImageIO and Foundation only, no UIKit, so a watchOS target can use it too. The caller wraps
// the CGImage (UIImage(cgImage:), Image(decorative:scale:)). Pure: no state, no logging (the
// caller logs its own event code), safe from any thread.
//
// The bytes themselves are bounded before this, while they arrive: `Transport.send(_:maxBytes:)`.

import Foundation
import ImageIO
import UniformTypeIdentifiers

public enum BoundedImage {
    /// The till's rules, as an example of a caller's choice (the till passes its own).
    public static let webRenditionTypes: Set<UTType> = [.jpeg, .png, .webP]

    /// Whether a header's size is a real one within `maxSourcePixels`. An overflowing product (a
    /// forged header) is refused, never wrapped (the reviewer's MUST on pos-app #141).
    public static func withinPixelBudget(width: Int, height: Int, maxSourcePixels: Int) -> Bool {
        guard width > 0, height > 0, maxSourcePixels > 0 else { return false }
        let (pixels, overflow) = width.multipliedReportingOverflow(by: height)
        return !overflow && pixels <= maxSourcePixels
    }

    /// The type ImageIO reads from the bytes, if it reads one.
    public static func type(of data: Data) -> UTType? {
        guard let source = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
              let identifier = CGImageSourceGetType(source) as String?
        else { return nil }
        return UTType(identifier)
    }

    /// The bytes as a bounded thumbnail, or nil when they aren't an allowed type, the header's
    /// size is missing or over `maxSourcePixels`, or the decode fails. `maxPixelSize` is the
    /// thumbnail's long side and must be positive.
    public static func thumbnail(_ data: Data, maxPixelSize: Int, maxSourcePixels: Int,
                                 allowedTypes: Set<UTType>) -> CGImage? {
        guard maxPixelSize > 0,
              let source = CGImageSourceCreateWithData(data as CFData, [kCGImageSourceShouldCache: false] as CFDictionary),
              let identifier = CGImageSourceGetType(source) as String?, let type = UTType(identifier),
              // Exact types, never "conforms to": .image would let every parser in.
              allowedTypes.contains(type),
              CGImageSourceGetCount(source) >= 1,
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let width = properties[kCGImagePropertyPixelWidth] as? Int,
              let height = properties[kCGImagePropertyPixelHeight] as? Int,
              withinPixelBudget(width: width, height: height, maxSourcePixels: maxSourcePixels)
        else { return nil }
        let options: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceThumbnailMaxPixelSize: maxPixelSize,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceShouldCacheImmediately: true,
        ]
        return CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary)
    }
}
