// KeyedLoaderTests.swift (v1.17, BOS #5563)
// ────────────────────────────────────────────────────────────────────
// KeyedLoader: one load per key, cancellation, the wipe, the cache. Each load
// here is a Gate the test opens by hand, so every interleaving is chosen, not
// raced: the reviewer's K1-K6 on #5563, the till's TillImages cases (#145,
// #146 SF2, #158) and the staff app's r3 case ("a joiner after a wipe gets
// nothing", mobile #152).

import Foundation
import Testing
@testable import WoodpatchCore

/// A load the test finishes by hand. Counts how often it started and whether
/// it saw its task cancelled.
private actor Gate {
    private var opened: Result<String, any Error>?
    private var waiting: [CheckedContinuation<Void, Never>] = []
    private(set) var starts = 0
    private(set) var sawCancel = false

    func load() async throws -> (value: String, cost: Int) {
        starts += 1
        while opened == nil {
            if Task.isCancelled { sawCancel = true; throw CancellationError() }
            await withCheckedContinuation { waiting.append($0) }
        }
        if Task.isCancelled { sawCancel = true }
        let value = try opened!.get()
        return (value, value.utf8.count)
    }

    func open(_ outcome: Result<String, any Error>) {
        opened = outcome
        wake()
    }

    /// Lets a load blocked in `load()` look at its cancellation again.
    func wake() {
        let all = waiting
        waiting = []
        for continuation in all { continuation.resume() }
    }
}

private struct Boom: Error, Equatable {}

@MainActor
private final class Flag {
    var on = true
}

@MainActor
struct KeyedLoaderTests {
    private func loader(countLimit: Int = 0, costLimit: Int = 0,
                        stillGood: @escaping @MainActor (String) -> Bool = { _ in true }) -> KeyedLoader<String, String> {
        KeyedLoader(countLimit: countLimit, costLimit: costLimit, stillGood: stillGood)
    }

    /// Lets the main actor run what's queued (a started task, a cancel hop).
    private func settle() async {
        for _ in 0 ..< 20 { await Task.yield() }
    }

    private func isCancellation(_ result: Result<String, any Error>) -> Bool {
        if case let .failure(error) = result { return error is CancellationError }
        return false
    }

    private func call(_ loader: KeyedLoader<String, String>, _ key: String, _ gate: Gate) -> Task<String, any Error> {
        Task { @MainActor in try await loader.value(for: key) { try await gate.load() } }
    }

    // MARK: - Single flight

    @Test func twoCallersShareOneLoad() async throws {
        let l = loader(), gate = Gate()
        let a = call(l, "k", gate), b = call(l, "k", gate)
        await settle()
        await gate.open(.success("v"))
        #expect(try await a.value == "v")
        #expect(try await b.value == "v")
        #expect(await gate.starts == 1)
    }

    @Test func aLoadedValueIsKept() async throws {
        let l = loader(), gate = Gate()
        await gate.open(.success("v"))
        _ = try await call(l, "k", gate).value
        _ = try await call(l, "k", gate).value
        #expect(await gate.starts == 1)
    }

    @Test func everyCallerGetsTheLoadsErrorAndNothingIsCached() async throws {
        let l = loader(), gate = Gate()
        let a = call(l, "k", gate), b = call(l, "k", gate)
        await settle()
        await gate.open(.failure(Boom()))
        #expect((await a.result).isFailure(Boom()))
        #expect((await b.result).isFailure(Boom()))
        let again = Gate()
        await again.open(.success("v"))
        #expect(try await call(l, "k", again).value == "v", "a failure isn't cached")
    }

    // MARK: - Cancellation (K3)

    @Test func aCancelledCallerReturnsAtOnceAndTheOtherStillGetsTheValue() async throws {
        let l = loader(), gate = Gate()
        let a = call(l, "k", gate), b = call(l, "k", gate)
        await settle()
        a.cancel()
        #expect(isCancellation(await a.result), "a returns before the load ends")
        await gate.open(.success("v"))
        #expect(try await b.value == "v")
        #expect(await gate.sawCancel == false, "b still wanted it")
    }

    @Test func theLastCallerToLeaveCancelsTheLoad() async {
        let l = loader(), gate = Gate()
        let a = call(l, "k", gate)
        await settle()
        a.cancel()
        #expect(isCancellation(await a.result))
        await settle()
        await gate.wake()
        await settle()
        #expect(await gate.sawCancel)
    }

    /// The till's #146 SF2: a load the last caller's going has cancelled is
    /// never joined; the next caller starts a new one.
    @Test func aCallerAfterACancelStartsANewLoad() async throws {
        let l = loader(), first = Gate()
        let a = call(l, "k", first)
        await settle()
        a.cancel()
        _ = await a.result
        await settle()
        let second = Gate()
        let b = call(l, "k", second)
        await settle()
        await second.open(.success("new"))
        #expect(try await b.value == "new")
        #expect(await second.starts == 1)
    }

    @Test func anAlreadyCancelledCallerNeverStartsALoad() async {
        let l = loader(), gate = Gate()
        let task = Task { @MainActor in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await l.value(for: "k") { try await gate.load() }
        }
        #expect(isCancellation(await task.result))
        #expect(await gate.starts == 0)
    }

    @Test func aLoadThatThrowsCancellationReachesItsCallersAsAnError() async {
        let l = loader(), gate = Gate()
        let a = call(l, "k", gate)
        await settle()
        await gate.open(.failure(CancellationError()))
        #expect(isCancellation(await a.result))
        let again = Gate()
        await again.open(.success("v"))
        #expect((try? await call(l, "k", again).value) == "v", "not cached")
    }

    // MARK: - K1: tokens

    /// An old load's late cleanup must not remove a newer load for the key.
    @Test func anOldLoadsLateFinishLeavesTheNewLoadJoinable() async throws {
        let l = loader(), first = Gate(), second = Gate()
        let a = call(l, "k", first)
        await settle()
        a.cancel()
        _ = await a.result
        let b = call(l, "k", second)
        await settle()
        // The first load now finishes (late), after the second started.
        await first.open(.success("old"))
        await settle()
        let joiner = Gate()
        let c = call(l, "k", joiner)
        await settle()
        await second.open(.success("new"))
        #expect(try await b.value == "new")
        #expect(try await c.value == "new", "the joiner joined the second load")
        #expect(await joiner.starts == 0)
    }

    // MARK: - The wipe (K2, K6)

    /// The staff app's r3 case, for a joiner AND for the caller that started
    /// the load: bytes loaded before a wipe reach nobody.
    @Test func aWipeDuringALoadAnswersEveryCallerCancelledAndCachesNothing() async {
        let l = loader(), gate = Gate()
        let starter = call(l, "k", gate)
        await settle()
        let joiner = call(l, "k", gate)
        await settle()
        l.removeAll()
        #expect(isCancellation(await starter.result))
        #expect(isCancellation(await joiner.result))
        await gate.open(.success("before the wipe"))
        await settle()
        let after = Gate()
        await after.open(.success("after"))
        #expect((try? await call(l, "k", after).value) == "after")
    }

    @Test func removingAKeyDuringItsLoadCancelsItsCallersAndCachesNothing() async {
        let l = loader(), gate = Gate()
        let a = call(l, "k", gate)
        await settle()
        l.remove("k")
        #expect(isCancellation(await a.result))
        await gate.open(.success("v"))
        await settle()
        let after = Gate()
        await after.open(.success("after"))
        #expect((try? await call(l, "k", after).value) == "after", "the removed key's load wasn't cached")
    }

    @Test func removingAKeyLeavesOtherKeysAlone() async throws {
        let l = loader(), gate = Gate(), other = Gate()
        let a = call(l, "a", gate), b = call(l, "b", other)
        await settle()
        l.remove("a")
        await other.open(.success("b"))
        #expect(isCancellation(await a.result))
        #expect(try await b.value == "b")
    }

    // MARK: - The cache (K4, K5)

    @Test func aStaleHitIsDroppedAndLoadedAgain() async throws {
        let fresh = Flag()
        let l = loader(stillGood: { _ in fresh.on })
        let first = Gate()
        await first.open(.success("old"))
        _ = try await call(l, "k", first).value
        fresh.on = false
        let second = Gate()
        await second.open(.success("new"))
        #expect(try await call(l, "k", second).value == "new")
        #expect(await second.starts == 1)
    }

    @Test func aWipeEmptiesTheCache() async throws {
        let l = loader(), first = Gate()
        await first.open(.success("old"))
        _ = try await call(l, "k", first).value
        l.removeAll()
        let second = Gate()
        await second.open(.success("new"))
        #expect(try await call(l, "k", second).value == "new")
    }

    @Test func boxedKeysAreEqualByValue() async throws {
        let l = loader(), first = Gate()
        await first.open(.success("v"))
        _ = try await call(l, String("k"), first).value
        let second = Gate()
        _ = try await call(l, ["k"].joined(), second).value
        #expect(await second.starts == 0, "an equal key found the kept value")
    }
}

private extension Result where Success == String, Failure == any Error {
    func isFailure(_ expected: Boom) -> Bool {
        if case let .failure(error) = self { return (error as? Boom) == expected }
        return false
    }
}
