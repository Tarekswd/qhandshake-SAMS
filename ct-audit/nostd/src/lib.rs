//! no_std entry points mirroring ../harness/src/main.rs, built per target and opt-level so that
//! scan_asm.py can walk each entry's call graph in the disassembly (targets Valgrind cannot run, e.g. thumbv6m).
#![no_std]
#![allow(deprecated)] // expanded-key API is what the Valgrind harness poisons; kept identical

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{ExpandedKeyEncoding, ml_kem_768};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Positive control: a secret-dependent 64-bit division. scan_asm.py must flag it on every target.
#[unsafe(no_mangle)]
pub extern "C" fn ct_control_div(a: u64, b: u64) -> u64 {
    a / b.max(1)
}

#[unsafe(no_mangle)]
pub extern "C" fn ct_mlkem_keygen(seed: &[u8; 64], ek_out: &mut [u8; 1184]) {
    let dk = ml_kem_768::DecapsulationKey::from_seed(ml_kem::Seed::from(*seed));
    ek_out.copy_from_slice(&dk.encapsulation_key().to_bytes());
}

#[unsafe(no_mangle)]
pub extern "C" fn ct_mlkem_encaps(seed: &[u8; 64], m: &[u8; 32], ct_out: &mut [u8; 1088], ss_out: &mut [u8; 32]) {
    let dk = ml_kem_768::DecapsulationKey::from_seed(ml_kem::Seed::from(*seed));
    let (ct, ss) = dk.encapsulation_key().encapsulate_deterministic(&ml_kem::array::Array::from(*m));
    ct_out.copy_from_slice(&ct);
    ss_out.copy_from_slice(&ss);
}

#[unsafe(no_mangle)]
pub extern "C" fn ct_mlkem_decaps(seed: &[u8; 64], ct: &[u8; 1088], ss_out: &mut [u8; 32]) {
    let exp = ml_kem_768::DecapsulationKey::from_seed(ml_kem::Seed::from(*seed)).to_expanded_bytes();
    let dk = ml_kem_768::DecapsulationKey::from_expanded(&exp).expect("valid expanded key");
    ss_out.copy_from_slice(&dk.decapsulate(&ml_kem::array::Array::from(*ct)));
}

#[unsafe(no_mangle)]
pub extern "C" fn ct_x25519(k: &[u8; 32], u: &[u8; 32], out: &mut [u8; 32]) {
    *out = x25519_dalek::x25519(*k, *u);
}
