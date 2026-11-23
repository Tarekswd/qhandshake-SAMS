//! Secret-poisoning harness: `ct-harness <target>` runs one operation with its secret inputs marked undefined for
//! Valgrind memcheck. Run under `valgrind --error-exitcode=99 ct-harness <target>`; every reported conditional
//! jump or address that depends on a secret is a candidate constant-time violation (ct-audit/README.md).
//! Inputs are fixed byte patterns, so every run of a target executes the same path.
//!
//! Targets:
//!   control_leak     MUST be reported (branch on a secret byte): proves the setup detects leaks
//!   control_clean    must NOT be reported (branch-free select)
//!   mlkem_keygen     DecapsulationKey::from_seed with the 64-byte seed secret (public rho is derived from it,
//!                    so reports in matrix sampling are expected and benign; see README)
//!   mlkem_encaps     encapsulate_deterministic with the message m secret, public encapsulation key
//!   mlkem_decaps     decapsulation of a valid ciphertext, secret parts of the expanded key (s, z) poisoned
//!   mlkem_decaps_bad same with a tampered ciphertext (implicit-rejection path)
//!   x25519           x25519(k, u) with the scalar k secret
//!   key_schedule     qhandshake handshake_secrets + finished_mac + verify_finished on a secret shared secret

#![allow(deprecated)] // expanded-key API: needed to poison only the secret parts of the key

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{ExpandedKeyEncoding, ml_kem_768};
use std::hint::black_box;

unsafe extern "C" {
    fn ct_poison(p: *mut u8, n: usize);
    fn ct_unpoison(p: *mut u8, n: usize);
    fn ct_check(p: *const u8, n: usize);
}

/// Mark secret. Takes `&mut` on purpose: the compiler must then assume the bytes changed and reload them from
/// memory, instead of using the compile-time constant it already knows (which would carry no taint).
fn poison(b: &mut [u8]) {
    unsafe { ct_poison(b.as_mut_ptr(), b.len()) }
}

/// Declassify an output so that using it afterwards (printing, comparing) is not reported. Checks first that the
/// output is still secret (one "client check" report per call is expected): otherwise the run proved nothing.
fn unpoison(b: &mut [u8]) {
    unsafe {
        ct_check(b.as_ptr(), b.len());
        ct_unpoison(b.as_mut_ptr(), b.len())
    }
}

fn pattern<const N: usize>(tag: u8) -> [u8; N] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(31).wrapping_add(tag))
}

// ML-KEM-768 expanded decapsulation key = dk_pke (384*k) || ek (384*k + 32) || H(ek) (32) || z (32), k = 3.
const DK_PKE: usize = 1152;
const EK: usize = 1184;

#[allow(deprecated)]
fn main() {
    let target = std::env::args().nth(1).unwrap_or_default();
    let mut seed = ml_kem::Seed::from(pattern::<64>(1));
    match target.as_str() {
        "control_leak" => {
            let mut s = pattern::<32>(7);
            poison(&mut s);
            if s[0] == 0 {
                println!("zero");
            }
        }
        "control_clean" => {
            let mut s = pattern::<32>(7);
            poison(&mut s);
            let mask = 0u8.wrapping_sub(s[0] & 1);
            let mut out = [(black_box(0xAAu8) & mask) | (black_box(0x55u8) & !mask)];
            unpoison(&mut out);
            black_box(out);
        }
        "mlkem_keygen" => {
            poison(&mut seed);
            let dk = ml_kem_768::DecapsulationKey::from_seed(seed);
            let mut ek = dk.encapsulation_key().to_bytes();
            unpoison(&mut ek);
            black_box(ek);
        }
        "mlkem_encaps" => {
            let dk = ml_kem_768::DecapsulationKey::from_seed(seed);
            let mut m = ml_kem::array::Array::from(pattern::<32>(3));
            poison(&mut m);
            let (mut ct, mut ss) = dk.encapsulation_key().encapsulate_deterministic(&m);
            unpoison(&mut ct);
            unpoison(&mut ss);
            black_box((ct, ss));
        }
        "mlkem_decaps" | "mlkem_decaps_bad" => {
            let dk0 = ml_kem_768::DecapsulationKey::from_seed(seed);
            let m = ml_kem::array::Array::from(pattern::<32>(3));
            let (mut ct, _) = dk0.encapsulation_key().encapsulate_deterministic(&m);
            if target == "mlkem_decaps_bad" {
                ct[17] ^= 0x01;
            }
            let mut exp = dk0.to_expanded_bytes();
            poison(&mut exp[..DK_PKE]);
            poison(&mut exp[DK_PKE + EK + 32..]);
            let dk = ml_kem_768::DecapsulationKey::from_expanded(&exp).expect("valid expanded key");
            let mut ss = dk.decapsulate(&ct);
            unpoison(&mut ss);
            black_box(ss);
        }
        "x25519" => {
            let mut k = pattern::<32>(5);
            let mut base = [0u8; 32];
            base[0] = 9; // RFC 7748 base point u = 9
            let u = x25519_dalek::x25519(pattern::<32>(9), base); // public peer value
            poison(&mut k);
            let mut out = x25519_dalek::x25519(k, u);
            unpoison(&mut out);
            black_box(out);
        }
        "key_schedule" => {
            use qhandshake::crypto::{finished_mac, handshake_secrets, hash, verify_finished};
            let mut shared = pattern::<64>(11);
            let th = hash(b"transcript");
            poison(&mut shared);
            let mut hs = handshake_secrets(&shared, &th);
            let mac = finished_mac(&hs.client_hs, &th);
            let ok = verify_finished(&hs.client_hs, &th, &mac).is_ok(); // the verdict is public by design
            unpoison(&mut hs.server_hs);
            black_box((ok, hs.server_hs));
        }
        _ => {
            eprintln!("unknown target; see the doc comment in src/main.rs");
            std::process::exit(2);
        }
    }
}
