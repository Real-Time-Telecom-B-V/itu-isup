//! Memory-leak check.
//!
//! A counting global allocator tracks **live bytes** (allocated − freed), RSS
//! is too noisy (the OS/allocator retains freed pages), but live bytes are
//! exact, so a real leak shows up as monotonic growth. Three phases:
//!
//!   1. **iam**, encode + decode an IAM with a called party number and an
//!      optional calling party number (the mandatory fixed part, the
//!      variable-part pointer arithmetic, address-signal BCD packing, and the
//!      optional-part TLV walk).
//!   2. **rel**, encode + decode a Release carrying Cause indicators (the
//!      single mandatory-variable path).
//!   3. **sup**, encode + decode the circuit-supervision messages (BLO / RSC /
//!      GRS / CGB): CIC-and-type-only, and the range-and-status variable part.
//!
//! Each phase asserts live bytes return to a flat baseline. Exits non-zero on a
//! leak. Driven by `scripts/mem_leak_test.sh`.
//!
//! Run: `cargo run --release --example leak_check`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

use itu_isup::{
    calling_party_category, CauseIndicators, Message, Number, Parameter, RangeAndStatus,
};

// ── Counting allocator ──────────────────────────────────────────────────────
static LIVE: AtomicI64 = AtomicI64::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, l, new_size);
        if !p.is_null() {
            LIVE.fetch_add(new_size as i64 - l.size() as i64, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

// ── Phase 1: IAM with optional calling party ────────────────────────────────
fn iam_cycle(iters: usize) {
    let called = Number::called(4, 1, false, "15551234567");
    let calling = Number::calling(4, 1, false, 0, 3, "15559876543");
    let iam = Message::iam(
        1,
        0x00,
        0x2000,
        calling_party_category::ORDINARY,
        0x00,
        &called,
    )
    .unwrap()
    .with_optional(Parameter::calling_party_number(&calling).unwrap());
    for _ in 0..iters {
        let bytes = iam.encode().unwrap();
        std::hint::black_box(Message::decode(&bytes).unwrap());
    }
}

// ── Phase 2: Release with Cause indicators ──────────────────────────────────
fn rel_cycle(iters: usize) {
    let rel = Message::release(1, &CauseIndicators::new(1, 16));
    for _ in 0..iters {
        let bytes = rel.encode().unwrap();
        std::hint::black_box(Message::decode(&bytes).unwrap());
    }
}

// ── Phase 3: circuit-supervision messages ───────────────────────────────────
fn sup_cycle(iters: usize) {
    let blo = Message::blocking(1);
    let rsc = Message::reset_circuit(1);
    let grs = Message::circuit_group_reset(1, &RangeAndStatus::range_only(4));
    let cgb = Message::circuit_group_blocking(1, 0x00, &RangeAndStatus::with_status(7, vec![0xFF]));
    for _ in 0..iters {
        std::hint::black_box(Message::decode(&blo.encode().unwrap()).unwrap());
        std::hint::black_box(Message::decode(&rsc.encode().unwrap()).unwrap());
        std::hint::black_box(Message::decode(&grs.encode().unwrap()).unwrap());
        std::hint::black_box(Message::decode(&cgb.encode().unwrap()).unwrap());
    }
}

fn report(phase: &str, base: i64) -> i64 {
    let growth = live() - base;
    println!("  {phase}: live = {} bytes (Δ {:+})", live(), growth);
    growth
}

fn main() {
    const ITERS: usize = 200_000;
    const CYCLES: usize = 10;
    const BUDGET: i64 = 64 * 1024;

    // Phase 1: IAM.
    println!("[iam] {CYCLES} x {ITERS} encode+decode round-trips (IAM + optional calling party)");
    iam_cycle(ITERS); // warm up
    let iam_base = live();
    for c in 1..=CYCLES {
        iam_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), iam_base);
    }
    let iam_growth = live() - iam_base;

    // Phase 2: Release.
    println!("\n[rel] {CYCLES} x {ITERS} encode+decode round-trips (Release with Cause)");
    rel_cycle(ITERS); // warm up
    let rel_base = live();
    for c in 1..=CYCLES {
        rel_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), rel_base);
    }
    let rel_growth = live() - rel_base;

    // Phase 3: circuit supervision.
    println!("\n[sup] {CYCLES} x {ITERS} encode+decode round-trips (BLO + RSC + GRS + CGB)");
    sup_cycle(ITERS); // warm up
    let sup_base = live();
    for c in 1..=CYCLES {
        sup_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), sup_base);
    }
    let sup_growth = live() - sup_base;

    // Verdict.
    println!();
    let mut ok = true;
    if iam_growth > BUDGET {
        eprintln!("FAIL: IAM live bytes grew {iam_growth} (> {BUDGET})");
        ok = false;
    }
    if rel_growth > BUDGET {
        eprintln!("FAIL: Release live bytes grew {rel_growth} (> {BUDGET})");
        ok = false;
    }
    if sup_growth > BUDGET {
        eprintln!("FAIL: supervision live bytes grew {sup_growth} (> {BUDGET})");
        ok = false;
    }
    if !ok {
        std::process::exit(1);
    }
    println!(
        "PASS: IAM Δ {iam_growth} ≤ {BUDGET}; REL Δ {rel_growth} ≤ {BUDGET}; SUP Δ {sup_growth} ≤ {BUDGET}"
    );
}
