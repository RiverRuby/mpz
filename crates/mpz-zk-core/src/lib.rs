mod prover;
mod store;
mod verifier;

pub use prover::{Prover, ProverError};
pub use verifier::{Verifier, VerifierError};

#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_memory_core::correlated::Delta;
    use mpz_ot_core::{
        ideal::cot::IdealCOT, test::assert_cot, RCOTReceiverOutput, RCOTSenderOutput,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_zk() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut cot = IdealCOT::new(rng.gen(), delta.into_inner());

        let (
            RCOTSenderOutput { msgs: keys, .. },
            RCOTReceiverOutput {
                choices,
                msgs: macs,
                ..
            },
        ) = cot.random_correlated(AES128.input_len() + AES128.and_count());

        let input_keys = &keys[..AES128.input_len()];
        let gate_keys = &keys[AES128.input_len()..];
        let input_macs = &macs[..AES128.input_len()];
        let gate_masks = &choices[AES128.input_len()..];
        let gate_macs = &macs[AES128.input_len()..];

        let mut prover = Prover::default();
        let mut verifier = Verifier::new(delta);

        let mut prover_iter = prover
            .execute(&AES128, input_macs, gate_masks, gate_macs)
            .unwrap();
        let mut verifier_consumer = verifier.execute(&AES128, input_keys, gate_keys).unwrap();

        for adjust in prover_iter.by_ref() {
            verifier_consumer.next(adjust);
        }

        let output_macs = prover_iter.finish().unwrap();
        let output_keys = verifier_consumer.finish().unwrap();
    }
}
