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

#[cfg(test)]
mod tests {
    use mpz_core::prg::Prg;
    use mpz_ot_core::{ideal::cot::IdealCOT, test::assert_cot};

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

        let (masks, prover_labels) = prover.compute_input_bits(&input, cot_receiver).unwrap();

        let verifier_labels = verifier.compute_input_bits(&masks, cot_sender).unwrap();

        assert_cot(delta, &input, &prover_labels, &verifier_labels);

        prover_labels
            .iter()
            .zip(verifier_labels.iter())
            .for_each(|(&mac, &key)| {
                let (cot_sender, cot_receiver) = ideal_cot.random_correlated(1);

                let mask = prover.compute_and_gate(mac, mac, cot_receiver).unwrap();

                verifier
                    .compute_and_gate(key, key, mask, cot_sender)
                    .unwrap();
            });

        let (VOPESenderOutput { eval, .. }, VOPEReceiverOutput { coeff, .. }) =
            ideal_vope.random_correlated(1);

        let (u, v) = prover.check_and_gate((coeff[0], coeff[1]));

        verifier.check_and_gate(eval, u, v);

        assert!(verifier.checked());
    }
}
