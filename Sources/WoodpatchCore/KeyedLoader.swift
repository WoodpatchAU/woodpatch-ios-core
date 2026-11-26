// KeyedLoader.swift (v1.17, BOS #5563)
// ────────────────────────────────────────────────────────────────────
// One load per key at a time, a capped memory cache, and a wipe that nothing
// outlives. Lifted from the till's TillImages (the in-flight, waiters and
// generation plumbing, after the reviewer's #145, #146 and #158 fixes), with
// frontend-ios's two asks for the staff app's PinnedMediaLoader and the
// reviewer's K1-K6 on #5563.
//
// The rules:
// - SINGLE FLIGHT: one load per key. A caller for a key that's loading joins
//   it; every caller sharing a load gets its value, or its error unchanged.
//   A failure is never cached.
// - CANCELLATION: a cancelled caller gets CancellationError AT ONCE, never
//   waiting for a shared load. The LAST caller to leave cancels the load, and
//   a load already cancelled is never joined: the next caller starts afresh
//   (the reviewer's SF2 on till #146). A load that itself throws
//   CancellationError while its callers are still there reaches them as an
//   error, like any other, and isn't cached.
// - THE WIPE: `removeAll()` bumps the generation, empties the cache, cancels
//   every load and answers every waiting caller CancellationError. A load
//   started before it is neither cached NOR returned, to the caller that
//   started it or to any that joined (the staff app's #150/#152 rule:
//   bytes fetched before a wipe never reach anyone). `remove(key)` does the
//   same for one key.
// - THE CACHE is NSCache, boxed: its limits are hints, and it may evict at
//   any time, so nothing here relies on a value staying. A value whose cost is
//   over `costLimit` may simply not be kept. `countLimit` 0 means no count
//   limit (NSCache's meaning).
// - `stillGood` runs on the main actor for every hit, so keep it cheap: it
//   must not block, and it can't await. A hit it rejects is dropped and loaded
//   again; the stale value is never returned.
//
// Each load is tracked by its own object (the token), and cleaned up only by
// that object, so an old load finishing late can never remove or answer a
// newer load for the same key (the reviewer's K1).
//
// The bookkeeping is on the main actor. The load runs wherever its closure
// runs: a @Sendable closure that isn't actor-isolated runs off the main actor.

import Foundation

@MainActor
public final class KeyedLoader<Key: Hashable & Sendable, Value: Sendable> {
    public typealias Load = @Sendable () async throws -> (value: Value, cost: Int)
    private typealias Loaded = (value: Value, cost: Int)

    /// NSCache wants class keys: equal and hashed by the key's Hashable.
    private final class KeyBox: NSObject {
        let key: Key
        init(_ key: Key) { self.key = key }
        override var hash: Int { key.hashValue }
        override func isEqual(_ object: Any?) -> Bool { (object as? KeyBox)?.key == key }
    }

    private final class ValueBox {
        let value: Value
        init(_ value: Value) { self.value = value }
    }

    /// One load in progress, and the callers waiting on it. On the main actor
    /// like the rest, which also lets a cancel handler hand it back there.
    @MainActor
    private final class Flight {
        let generation: Int
        var task: Task<Void, Never>?
        var waiters: [UUID: CheckedContinuation<Loaded, any Error>] = [:]
        /// Cancelled (every caller left), or given up by remove / removeAll: it
        /// answers nobody and caches nothing.
        var abandoned = false

        init(generation: Int) { self.generation = generation }
    }

    private let cache = NSCache<KeyBox, ValueBox>()
    private let stillGood: @MainActor (Value) -> Bool
    private var inFlight: [Key: Flight] = [:]
    private var generation = 0

    public init(countLimit: Int, costLimit: Int, stillGood: @escaping @MainActor (Value) -> Bool = { _ in true }) {
        cache.countLimit = countLimit
        cache.totalCostLimit = costLimit
        self.stillGood = stillGood
    }

    /// The kept value if it's still good, else the result of one shared load.
    /// Throws the load's error, or CancellationError if this caller was
    /// cancelled or the key was removed (or everything was) while it waited.
    public func value(for key: Key, load: @escaping Load) async throws -> Value {
        try Task.checkCancellation()
        let box = KeyBox(key)
        if let kept = cache.object(forKey: box) {
            if stillGood(kept.value) { return kept.value }
            cache.removeObject(forKey: box)
        }
        let flight = inFlight[key].flatMap { $0.abandoned ? nil : $0 } ?? start(key, load)
        let waiter = UUID()
        let loaded = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Loaded, any Error>) in
                // Runs at once, on the main actor, before any cancel handler's hop.
                if Task.isCancelled || flight.abandoned {
                    continuation.resume(throwing: CancellationError())
                } else {
                    flight.waiters[waiter] = continuation
                }
            }
        } onCancel: {
            Task { @MainActor in self.leave(flight, key: key, waiter: waiter) }
        }
        return loaded.value
    }

    /// Forgets `key`'s value. A load in flight for it is cancelled: it isn't
    /// cached, and its callers get CancellationError.
    public func remove(_ key: Key) {
        cache.removeObject(forKey: KeyBox(key))
        if let flight = inFlight.removeValue(forKey: key) { abandon(flight) }
    }

    /// Forgets everything and cancels every load: nothing started before it is
    /// cached or returned after it.
    public func removeAll() {
        generation += 1
        cache.removeAllObjects()
        let flights = inFlight.values
        inFlight = [:]
        for flight in flights { abandon(flight) }
    }

    // MARK: - Internals

    private func start(_ key: Key, _ load: @escaping Load) -> Flight {
        let flight = Flight(generation: generation)
        inFlight[key] = flight
        flight.task = Task { [weak self] in
            let outcome: Result<Loaded, any Error>
            do { outcome = .success(try await load()) } catch { outcome = .failure(error) }
            self?.finish(flight, key: key, outcome)
        }
        return flight
    }

    private func finish(_ flight: Flight, key: Key, _ outcome: Result<Loaded, any Error>) {
        // Only this load's own entry (K1): a newer load for the key stays.
        if inFlight[key] === flight { inFlight[key] = nil }
        guard !flight.abandoned, flight.generation == generation else {
            answer(flight, with: .failure(CancellationError()))
            return
        }
        if case let .success(loaded) = outcome {
            cache.setObject(ValueBox(loaded.value), forKey: KeyBox(key), cost: max(0, loaded.cost))
        }
        answer(flight, with: outcome)
    }

    /// A caller went away: it gets CancellationError now. The last one to go
    /// cancels the load, and nobody joins it after that.
    private func leave(_ flight: Flight, key: Key, waiter: UUID) {
        guard let continuation = flight.waiters.removeValue(forKey: waiter) else { return }
        continuation.resume(throwing: CancellationError())
        if flight.waiters.isEmpty, !flight.abandoned {
            if inFlight[key] === flight { inFlight[key] = nil }
            abandon(flight)
        }
    }

    private func abandon(_ flight: Flight) {
        flight.abandoned = true
        flight.task?.cancel()
        answer(flight, with: .failure(CancellationError()))
    }

    private func answer(_ flight: Flight, with outcome: Result<Loaded, any Error>) {
        let waiters = flight.waiters
        flight.waiters = [:]
        for continuation in waiters.values { continuation.resume(with: outcome) }
    }
}
