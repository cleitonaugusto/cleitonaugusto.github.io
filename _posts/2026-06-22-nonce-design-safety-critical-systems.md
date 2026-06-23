---
layout: post
title: "Nonce Design for Safety-Critical Systems: Lessons from a Post-Quantum MAVLink Protocol"
date: 2026-06-22
tags: [rust, security, embedded, post-quantum, MAVLink]
excerpt: "Building replay-attack resistance for drone command-and-control links — and the three non-obvious decisions that make it work."
---

Replay attacks on drone command links are not theoretical. A ground station sends `ARM` at timestamp T. An adversary records the packet. Thirty seconds later they retransmit it verbatim. If the drone accepts it, you have a serious problem — and in a jammed or contested environment, the attacker can do this silently.

The standard defense is a monotonically increasing nonce: every packet carries a counter, and the receiver only accepts packets with counters strictly greater than the last accepted value. Simple in concept. The implementation details are where things get interesting.

This post walks through the nonce design in [CleitonQ](https://github.com/cleitonaugusto/CleitonQ), a post-quantum authentication layer for MAVLink v2, and the three decisions that are non-obvious but matter for security.

---

## The Problem: Concurrent Control Loops

A drone's onboard software runs several concurrent threads: a 100 Hz telemetry loop, a command processor, and potentially a mesh relay. All of them sign outbound packets. All of them need nonces.

The naive implementation is a shared `u64` behind a `Mutex`. It works. It's also a footgun: if two threads call `next_nonce()` simultaneously without proper synchronization, they can read the same value, both increment to the same next value, and emit duplicate nonces. The receiver sees the duplicate and treats it as a replay — silently dropping a legitimate command.

In a flight-critical system, a dropped command is not an acceptable error mode.

The second naive implementation is `fetch_add` on an `AtomicU64`:

```rust
// Tempting, but has a subtle problem
fn next(&self) -> u64 {
    self.0.fetch_add(1, Ordering::Relaxed)
}
```

This fixes the race. But it wraps silently at `u64::MAX`. After 18.4 quintillion packets — unlikely in practice, but not impossible over the lifetime of a long-running system — nonce 0 becomes valid again. An adversary who stored a packet from the beginning of time can now replay it.

---

## Decision 1: Saturate, Don't Wrap

CleitonQ's `AtomicNonce::next()` uses a compare-and-exchange loop that saturates at `u64::MAX` instead of wrapping:

```rust
pub fn next(&self) -> u64 {
    let mut current = self.0.load(Ordering::Relaxed);
    loop {
        if current == u64::MAX {
            return u64::MAX;  // channel is exhausted, not rolled over
        }
        match self.0.compare_exchange(
            current, current + 1,
            Ordering::Relaxed, Ordering::Relaxed,
        ) {
            Ok(_) => return current,
            Err(observed) => current = observed,
        }
    }
}
```

When the counter saturates, the receiver rejects `u64::MAX` as a replay (it was already accepted). The channel stops working. That is the correct behavior: a locked channel surfaces as an observable failure — an operator sees it, investigates, and re-establishes the session. A silently rolled-over channel surfaces as an intermittent security hole that nobody notices until it's too late.

**Fail loudly rather than fail silently.** In safety-critical systems, this principle is not optional.

The CAS loop also handles the race correctly: if two threads read the same `current`, one wins the exchange and the other retries with the updated value. No duplicates, no locks.

---

## Decision 2: Memory Ordering Is Not Symmetric

The sender (`AtomicNonce`) and the receiver (`NonceTracker`) have different memory ordering requirements, and they are not interchangeable.

`AtomicNonce::next()` uses `Relaxed` for both the load and the CAS. This is intentional. The only property needed is that each call returns a unique, strictly increasing value. There is no requirement that the nonce emission *happens-before* anything else in the caller's memory. The packet containing the nonce will be serialized and sent over the network — the network ordering establishes the happens-before relationship with the receiver. Using `SeqCst` here would be correct but unnecessary, adding synchronization overhead on every outbound packet in a 100 Hz loop.

`NonceTracker::accept()` is different:

```rust
pub fn accept(&self, nonce: u64) -> bool {
    let mut current = self.0.load(Ordering::Acquire);
    loop {
        if nonce <= current {
            return false;
        }
        match self.0.compare_exchange(
            current, nonce,
            Ordering::AcqRel, Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}
```

The receiver uses `Acquire` on the load and `AcqRel` on the successful exchange. This establishes a happens-before edge: any thread that subsequently reads the tracker's value with `Acquire` sees all writes that preceded the accepted nonce. In practice this means: the authentication check that accepted a packet happens-before any processing of that packet's payload. If two threads race to accept the same nonce, exactly one wins the CAS — the other sees `nonce <= current` on retry and returns `false`.

Using `Relaxed` on the receiver would be wrong. It would allow a theoretical reordering where a thread begins processing a payload before the nonce check completes — which, in a language with a memory model that permits this, is a real vulnerability class.

---

## Decision 3: Process Restarts Without Persistent State

What happens when the companion computer reboots mid-flight? The `AtomicU64` in RAM is gone. If the new process starts from 0, every nonce it emits is below the receiver's `last_accepted` — the channel is dead until a new session is established.

One answer is NVRAM persistence: write the nonce to flash periodically, read it on boot. This works but adds I/O latency on the critical path and creates a new failure mode: flash write corruption during power loss.

`AtomicNonce::from_time()` takes a different approach:

```rust
pub fn from_time() -> Self {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Self::new(u64::try_from(nanos).unwrap_or(u64::MAX))
}
```

Seeding from nanoseconds since the Unix epoch means a restarted process almost certainly starts with nonces higher than anything emitted before the restart. A 10-second reboot adds 10 billion nonces of headroom. A 1-millisecond glitch adds 1 million. The wall clock is the implicit persistent store.

This relies on the system clock being monotonic across reboots — which is true on any platform with a battery-backed RTC and NTP. On systems without one (some deeply embedded targets), `from_time()` is unavailable and the application must manage initial nonce values explicitly.

The deeper architectural answer is that CleitonQ's session boundary makes this largely moot: a reboot forces a new ML-KEM session, which establishes a new session key. Since nonces are checked within a session (HMAC tags include the session key), cross-session replay is impossible regardless of nonce values.

---

## The Embedded Target

Not all targets have 64-bit atomics. Cortex-M4 (the processor in most Pixhawk flight controllers) does not. For these, CleitonQ provides `SimpleNonce` and `SimpleNonceTracker`:

```rust
pub struct SimpleNonce(u64);

impl SimpleNonce {
    pub fn next_nonce(&mut self) -> u64 {
        let v = self.0;
        self.0 = self.0.wrapping_add(1);
        v
    }
}
```

These are not thread-safe — the `&mut self` receiver makes that explicit at the type level. On a single-threaded embedded executor, this is correct and zero-overhead. On a multi-threaded target with 64-bit atomics, the compiler will refuse to compile the single-threaded variant in a shared context.

The platform split is expressed via `#[cfg(target_has_atomic = "64")]`, not runtime checks — it's a compile-time guarantee, not a runtime assertion.

---

## Testing the Properties

Three properties need tests, not documentation.

**Uniqueness under concurrency** — 8 threads each calling `next()` 1000 times should produce 8000 distinct nonces:

```rust
let n = Arc::new(AtomicNonce::new(0));
let threads: Vec<_> = (0..8)
    .map(|_| {
        let n = Arc::clone(&n);
        thread::spawn(move || (0..1000).map(|_| n.next()).collect::<Vec<_>>())
    })
    .collect();

let mut all = HashSet::new();
for t in threads {
    for nonce in t.join().unwrap() {
        assert!(all.insert(nonce), "duplicate nonce — race in AtomicNonce::next");
    }
}
assert_eq!(all.len(), 8000);
```

**Replay rejection** — the tracker must reject exact replays and regressions:

```rust
let t = NonceTracker::new(0);
assert!(t.accept(5));
assert!(!t.accept(5));   // exact replay
assert!(!t.accept(3));   // regression
assert!(t.accept(6));    // forward progress
```

**No double-accept under concurrency** — 4 threads racing to accept nonces 1..=500 should produce exactly 500 total acceptances:

```rust
let tracker = Arc::new(NonceTracker::new(0));
// 4 threads, each tries to accept all 500 nonces
let total_accepted: usize = threads.into_iter()
    .map(|t| t.join().unwrap())
    .sum();
assert_eq!(total_accepted, 500);
assert_eq!(tracker.last_accepted(), 500);
```

These tests run on every CI push, including on a Neoverse-N2 ARM64 runner that mirrors the hardware profile of production companion computers.

---

## The Broader Point

Nonce design looks simple until you consider the combination of concurrent writers, concurrent readers, process restarts, and an adversary who stores packets indefinitely. Each of those constraints pushes the design in a different direction. Getting all four right simultaneously requires explicit reasoning about each decision — not just picking the first implementation that passes the unit tests.

The three decisions above — saturating arithmetic, asymmetric memory ordering, and clock-seeded initialization — are each defensible in isolation. Together they form a design that fails loudly, maintains happens-before guarantees where they matter, and survives the most common production failure mode (process restart) without persistent state.

CleitonQ is open source under MIT OR Apache-2.0. The full nonce implementation, with all tests, is in [`src/nonce.rs`](https://github.com/cleitonaugusto/CleitonQ/blob/main/src/nonce.rs).

---

*CleitonQ is a post-quantum authentication layer for MAVLink v2, combining ML-KEM-1024 (FIPS 203) for session establishment and ML-DSA-87 (FIPS 204) for command signing. A formal security model in ProVerif 2.05 verifies session key secrecy (Q1) and command authenticity (Q2) against a Dolev-Yao attacker. [Paper on Zenodo](https://doi.org/10.5281/zenodo.20776349).*
