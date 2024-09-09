//! This is the implementation of QuickSilver (https://eprint.iacr.org/2021/076.pdf).

mod error;
mod prover;
mod verifier;

pub use error::*;
pub use prover::Prover;
pub use verifier::Verifier;

use serde::{Deserialize, Serialize};

/// Buffer size of each check.
pub(crate) const CHECK_BUFFER_SIZE: usize = 1024 * 1024;

/// Default amount of authenticated gates per batch.
pub(crate) const DEFAULT_BATCH_SIZE: usize = 128;

#[inline]
fn bools_to_bytes(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}

/// A batch of bit masks.
///
/// # Parameters
///
/// - `N`: The size of a batch
#[derive(Debug, Serialize, Deserialize)]
pub struct MaskBitBatch<const N: usize = DEFAULT_BATCH_SIZE>(
    #[serde(with = "serde_arrays")] [bool; N],
);

impl<const N: usize> MaskBitBatch<N> {
    /// Create a new batch of mask bits.
    pub fn new(batch: [bool; N]) -> Self {
        Self(batch)
    }
}

#[cfg(test)]
mod tests {
    use mpz_core::prg::Prg;
    use mpz_ot_core::{
        ideal::cot::IdealCOT, test::assert_cot, RCOTReceiverOutput, RCOTSenderOutput,
    };

    use crate::{ideal::vope::IdealVOPE, VOPEReceiverOutput, VOPESenderOutput};

    use super::{Prover, Verifier};

    #[test]
    fn test_qs_core() {
        let mut prg = Prg::new();
        let mut input = vec![false; 100];
        prg.random_bools(&mut input);

        let mut ideal_cot = IdealCOT::default();
        let mut ideal_vope = IdealVOPE::default();

        let mut delta = ideal_cot.delta();
        delta.set_lsb();

        ideal_vope.set_delta(delta);

        let mut prover = Prover::new();
        let mut verifier = Verifier::new(delta);

        let (cot_sender, cot_receiver) = ideal_cot.random_correlated(input.len());

        let (masks, prover_labels) = prover.auth_input_bits(&input, cot_receiver).unwrap();

        let verifier_labels = verifier.auth_input_bits(&masks, cot_sender).unwrap();

        assert_cot(delta, &input, &prover_labels, &verifier_labels);

        prover_labels
            .iter()
            .zip(verifier_labels.iter())
            .for_each(|(&mac, &key)| {
                let (cot_sender, cot_receiver) = ideal_cot.random_correlated(1);

                let RCOTReceiverOutput {
                    choices: s,
                    msgs: blks,
                    ..
                } = cot_receiver;

                let (mask, _) = prover.auth_and_gate(mac, mac, (s[0], blks[0])).unwrap();

                let RCOTSenderOutput { msgs: blks, .. } = cot_sender;

                verifier.auth_and_gate(key, key, mask, blks[0]).unwrap();
            });

        let (VOPESenderOutput { eval, .. }, VOPEReceiverOutput { coeff, .. }) =
            ideal_vope.random_correlated(1);

        let (u, v) = prover.check_and_gates((coeff[0], coeff[1]));

        verifier.check_and_gates(eval, u, v);

        assert!(verifier.checked());
    }
}
