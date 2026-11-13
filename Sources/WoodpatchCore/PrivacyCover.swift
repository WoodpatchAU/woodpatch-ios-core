// PrivacyCover.swift (v1.9, BOS #4160 item 4, from the POS app's #3920;
// v1.10 puts the keyboard away)
// ────────────────────────────────────────────────────────────────────
// Hides the app whenever a scene stops being active, so the App Switcher
// snapshot never shows what was on screen (a cart, an amount, a caller, a
// customer's name).
//
// The cover is its own window, above everything else in the scene. An overlay
// on the root view isn't enough: sheets, alerts and dialogs are presented
// ABOVE the root view, so their contents go into the snapshot uncovered. A
// window above them covers whatever is showing, including anything presented
// later, with nothing for a new sheet to remember.
//
// It follows UIKit's scene notifications rather than SwiftUI's scenePhase:
// they're posted synchronously as the scene resigns, before iOS takes the
// snapshot. The window is made ahead, hidden, as the scene connects, and its
// own background is opaque, so a deactivation only shows it: covered from the
// first frame, before SwiftUI has drawn the app's cover content (reviewer, POS
// #86 S1).
//
// Not key, never focused. But it DOES take touches while shown, deliberately,
// so nothing under it can be used.
//
// THE KEYBOARD (v1.10, Chris's App Switcher screenshot on the till,
// 2026-11-13): the system keyboard's window sits above any window an app can
// make, so a keyboard left up was drawn over the cover, with its suggestion
// bar able to show what was typed. Raising the cover's level doesn't help
// (tried at 10,000,001 on iPhone and iPad: the keyboard still shows). So as the
// cover goes up, editing ends in the scene's other windows, without animation,
// so the keyboard is gone before the snapshot. The field doesn't get its
// focus back when the scene returns: the user taps it again.
//
// It also shows under a system prompt over the app (a permission alert, a call
// taken full screen), until the prompt is dismissed. That's the safe side, but
// an app whose own flow brings a system sheet up (CallKit's, Apple Pay's,
// Tap to Pay's) should check what its users then see.
//
// Usage, once at launch, before any scene connects or as early as possible:
//
//     PrivacyCover.shared.start { PrivacyCoverView(label: "Till hidden") }

import SwiftUI
import UIKit

@MainActor
public final class PrivacyCover {
    public static let shared = PrivacyCover()

    /// One cover per scene: an iPad can show the app in more than one window.
    private var windows: [ObjectIdentifier: UIWindow] = [:]
    private var observers: [any NSObjectProtocol] = []
    private var content: (@MainActor () -> AnyView)?

    private init() {}

    /// Starts following every scene of the app, covering each with `cover`.
    /// Once, at launch: a second call changes nothing.
    public func start<Cover: View>(@ViewBuilder cover: @escaping @MainActor () -> Cover) {
        guard observers.isEmpty else { return }
        content = { AnyView(cover()) }
        observers = [
            Self.observe(UIScene.willConnectNotification) { _ = $0.window(for: $1) },
            Self.observe(UIScene.willDeactivateNotification) { $0.cover($1) },
            Self.observe(UIScene.didActivateNotification) { $0.window(for: $1)?.isHidden = true },
            Self.observe(UIScene.didDisconnectNotification) { $0.windows[$1] = nil },
        ]
        // A scene that connected before this ran.
        for scene in UIApplication.shared.connectedScenes { _ = window(for: ObjectIdentifier(scene)) }
    }

    /// Shows the scene's cover and puts the keyboard away under it.
    private func cover(_ id: ObjectIdentifier) {
        guard let window = window(for: id) else { return }
        window.isHidden = false
        guard let scene = window.windowScene else { return }
        UIView.performWithoutAnimation {
            for other in scene.windows where other !== window { other.endEditing(true) }
        }
    }

    /// The scene's cover if it's made yet, without making it. For tests.
    public func preparedWindow(_ scene: UIScene) -> UIWindow? { windows[ObjectIdentifier(scene)] }

    /// The scene's cover, made (hidden) on first asking.
    private func window(for id: ObjectIdentifier) -> UIWindow? {
        if let window = windows[id] { return window }
        guard let content else { return nil }
        let scene = UIApplication.shared.connectedScenes.first { ObjectIdentifier($0) == id }
        guard let scene = scene as? UIWindowScene else { return nil }
        let window = UIWindow(windowScene: scene)
        // Above an alert's level too, so nothing the app presents can sit over it.
        window.windowLevel = .alert + 1
        // Opaque the instant it's shown, before its SwiftUI content first renders.
        window.backgroundColor = .systemBackground
        window.rootViewController = UIHostingController(rootView: content())
        window.isHidden = true
        windows[id] = window
        return window
    }

    /// Calls `action` on the main thread with the scene's identity (a Sendable
    /// handle; the scene itself is looked up again on the main actor).
    private static func observe(
        _ name: Notification.Name,
        _ action: @escaping @MainActor (PrivacyCover, ObjectIdentifier) -> Void
    ) -> any NSObjectProtocol {
        NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { note in
            guard let scene = note.object as AnyObject? else { return }
            let id = ObjectIdentifier(scene)
            MainActor.assumeIsolated { action(.shared, id) }
        }
    }
}

/// A plain cover: the system background and a lock. One accessibility
/// element (`label`, identifier "privacyCover"), so UI tests can find it, and
/// nothing behind it is reachable, VoiceOver included.
public struct PrivacyCoverView: View {
    let label: String

    public init(label: String) {
        self.label = label
    }

    public var body: some View {
        ZStack {
            Color(.systemBackground)
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
        }
        .ignoresSafeArea()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityIdentifier("privacyCover")
    }
}
