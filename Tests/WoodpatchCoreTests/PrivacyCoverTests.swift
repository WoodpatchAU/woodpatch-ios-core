// PrivacyCoverTests.swift (v1.9, v1.10)
// The App Switcher cover is ready BEFORE the scene first goes inactive: made,
// hidden, opaque and above alerts, so going inactive only shows it. And the
// notifications drive it: shown on willDeactivate, hidden on didActivate.
// v1.10: going inactive also puts the keyboard away, since the system
// keyboard's window is drawn above the cover.
// These run in Tests/Host, whose scene has connected by now.

import Testing
import UIKit
@testable import WoodpatchCore

@MainActor
@Suite(.serialized)
struct PrivacyCoverTests {
    private var scenes: [UIWindowScene] {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    }

    init() {
        PrivacyCover.shared.start { PrivacyCoverView(label: "Hidden") }
    }

    @Test func aSceneConnectedBeforeStartIsCoveredAhead() throws {
        try #require(!scenes.isEmpty, "the test host has no scene")
        for scene in scenes {
            #expect(PrivacyCover.shared.preparedWindow(scene) != nil, "no cover made ahead")
        }
    }

    @Test func theCoverIsHiddenOpaqueAndAboveAlerts() throws {
        let scene = try #require(scenes.first, "no scene in the test host")
        let window = try #require(PrivacyCover.shared.preparedWindow(scene))
        #expect(window.isHidden, "covered while active")
        #expect(!window.isKeyWindow)
        #expect(window.windowLevel > .alert)
        var alpha: CGFloat = 0
        window.backgroundColor?.getWhite(nil, alpha: &alpha)
        #expect(alpha == 1, "the cover's own background isn't opaque")
    }

    @Test func deactivatingShowsItAndActivatingHidesIt() throws {
        let scene = try #require(scenes.first, "no scene in the test host")
        let window = try #require(PrivacyCover.shared.preparedWindow(scene))
        NotificationCenter.default.post(name: UIScene.willDeactivateNotification, object: scene)
        #expect(!window.isHidden, "not shown as the scene resigned")
        NotificationCenter.default.post(name: UIScene.didActivateNotification, object: scene)
        #expect(window.isHidden, "still covering after the scene came back")
    }

    @Test func deactivatingPutsTheKeyboardAway() throws {
        let scene = try #require(scenes.first, "no scene in the test host")
        let cover = try #require(PrivacyCover.shared.preparedWindow(scene))
        let host = try #require(scene.windows.first { $0 !== cover && !$0.isHidden }, "no app window")
        let field = UITextField(frame: CGRect(x: 0, y: 0, width: 200, height: 40))
        host.addSubview(field)
        defer { field.removeFromSuperview() }
        host.makeKey()
        try #require(field.becomeFirstResponder(), "the field couldn't take focus to begin with")
        NotificationCenter.default.post(name: UIScene.willDeactivateNotification, object: scene)
        #expect(!field.isFirstResponder, "still editing under the cover, so the keyboard shows over it")
        NotificationCenter.default.post(name: UIScene.didActivateNotification, object: scene)
    }

    @Test func aSecondStartChangesNothing() throws {
        let scene = try #require(scenes.first, "no scene in the test host")
        let before = try #require(PrivacyCover.shared.preparedWindow(scene))
        PrivacyCover.shared.start { PrivacyCoverView(label: "Other") }
        #expect(PrivacyCover.shared.preparedWindow(scene) === before)
    }
}
