//! This is the implementation of QuickSilver (https://eprint.iacr.org/2021/076.pdf).

mod error;
mod prover;
mod verifier;

pub use error::*;
pub use prover::Prover;
pub use verifier::Verifier;

/// Buffer size of each check.
pub(crate) const CHECK_BUFFER_SIZE: usize = 1024 * 1024;

/// Convert bool vector to byte vector.
#[inline]
pub fn bools_to_bytes(bv: &[bool]) -> Vec<u8> {
    let offset = if bv.len() % 8 == 0 { 0 } else { 1 };
    let mut v = vec![0u8; bv.len() / 8 + offset];
    for (i, b) in bv.iter().enumerate() {
        v[i / 8] |= (*b as u8) << (7 - (i % 8));
    }
    v
}

/// Convert byte vector to bool vector.
#[inline]
pub fn bytes_to_bools(v: &[u8]) -> Vec<bool> {
    let mut bv = Vec::with_capacity(v.len() * 8);
    for byte in v.iter() {
        for i in 0..8 {
            bv.push(((byte >> (7 - i)) & 1) != 0);
        }
    }
    bv
}

#[cfg(test)]
mod tests {
    use mpz_core::prg::Prg;
    use mpz_ot_core::{
        ideal::cot::IdealCOT, test::assert_cot, RCOTReceiverOutput, RCOTSenderOutput,
    };

    use crate::ideal::vope::IdealVOPE;

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

                let (mask, _) = prover.auth_and_gate(mac, mac, (s[0], blks[0]));

                let RCOTSenderOutput { msgs: blks, .. } = cot_sender;

                verifier.auth_and_gate(key, key, mask, blks[0]);
            });

        let (vope_sender, vope_receiver) = ideal_vope.random_correlated(1);

        let (u, v) = prover.check_and_gates(vope_receiver);

        verifier.check_and_gates(vope_sender, u, v);

        assert!(verifier.checked());
    }
}
