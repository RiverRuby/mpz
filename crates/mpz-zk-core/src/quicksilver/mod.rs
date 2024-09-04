//! This is the implementation of QuickSilver (https://eprint.iacr.org/2021/076.pdf).

mod error;
mod prover;
mod verifier;

pub use error::*;
pub use prover::Prover;
pub use verifier::Verifier;

/// Buffer size of each check.
pub const CHECK_BUFFER_SIZE: usize = 1024 * 1024;

#[inline]
fn bools_to_bytes(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}
