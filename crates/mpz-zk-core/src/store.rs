mod prover;
mod verifier;

pub use prover::{ProverStore, ProverStoreError};
pub use verifier::{VerifierStore, VerifierStoreError};

use blake3::Hash;
use mpz_core::{bitvec::BitVec, Block};
use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

#[derive(Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct AssignPayload {
    idx: RangeSet<usize>,
    adjust: BitVec,
}

#[derive(Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct DecodePayload {
    idx: RangeSet<usize>,
    key_bits: BitVec,
}

#[derive(Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct MacPayload {
    idx: RangeSet<usize>,
    bits: BitVec,
    proof: Hash,
}

#[cfg(test)]
mod tests {
    use mpz_core::bitvec::{BitSlice, BitVec};
    use mpz_memory_core::correlated::Delta;
    use mpz_ot_core::{
        ideal::cot::IdealCOT, COTReceiverOutput, RCOTReceiverOutput, RCOTSenderOutput,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    struct Provider {
        idx_keys: usize,
        keys: Vec<Block>,
        idx_data: usize,
        data: BitVec,
        macs: Vec<Block>,
    }

    impl Provider {
        fn new(count: usize, delta: Delta) -> Self {
            let mut cot = IdealCOT::default();
            cot.set_delta(delta.into_inner());
            let (
                RCOTSenderOutput { msgs: keys, .. },
                RCOTReceiverOutput {
                    choices: data,
                    msgs: macs,
                    ..
                },
            ) = cot.random_correlated(count);

            Self {
                idx_keys: 0,
                keys,
                idx_data: 0,
                data: BitVec::from_iter(data),
                macs,
            }
        }

        fn provide_keys(&mut self, len: usize) -> &[Block] {
            let idx = self.idx_keys;
            self.idx_keys += len;
            &self.keys[idx..idx + len]
        }

        fn provide_macs(&mut self, len: usize) -> (&BitSlice, &[Block]) {
            let idx = self.idx_data;
            self.idx_data += len;
            (&self.data[idx..idx + len], &self.macs[idx..idx + len])
        }
    }

    #[test]
    fn test_store() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut provider = Provider::new(256, delta);

        let mut verifier = VerifierStore::new(delta);
        let mut prover = ProverStore::default();

        let val_a = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let val_b = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

        let ref_a_verifier = verifier.alloc_with(provider.provide_keys(128));
        let ref_b_verifier = verifier.alloc_with(provider.provide_keys(128));

        let (data, macs) = provider.provide_macs(128);
        let ref_a_prover = prover.alloc_with(data, macs);
        let (data, macs) = provider.provide_macs(128);
        let ref_b_prover = prover.alloc_with(data, macs);

        verifier.assign_public(ref_a_verifier, &val_a).unwrap();
        verifier.assign_blind(ref_b_verifier).unwrap();

        prover.assign_public(ref_a_prover, &val_a).unwrap();
        prover.assign_private(ref_b_prover, &val_b).unwrap();

        let payload = prover.execute_assign().unwrap();
        verifier.execute_assign(payload).unwrap();

        let mut fut_a_verifier = verifier.decode(ref_a_verifier).unwrap();
        let mut fut_b_verifier = verifier.decode(ref_b_verifier).unwrap();

        let _ = prover.decode(ref_a_prover).unwrap();
        let _ = prover.decode(ref_b_prover).unwrap();

        let payload = prover.execute_decode().unwrap();
        verifier.verify_data(payload).unwrap();
        verifier.execute_decode().unwrap();

        let (val_a_verifier, val_b_verifier) = (
            fut_a_verifier.try_recv().unwrap().unwrap(),
            fut_b_verifier.try_recv().unwrap().unwrap(),
        );

        assert_eq!(val_a_verifier, val_a);
        assert_eq!(val_b_verifier, val_b);
    }

    // #[test]
    // fn test_store_verifier_wants_assign_public() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     let a = verifier.alloc(128);

    //     verifier
    //         .assign_public(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
    //         .unwrap();

    //     assert!(verifier.wants_assign());
    // }

    // #[test]
    // fn test_store_verifier_wants_assign_blind() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     let a = verifier.alloc(128);

    //     verifier.assign_blind(a).unwrap();

    //     assert!(verifier.wants_assign());
    // }

    // #[test]
    // fn test_store_verifier_does_not_want_assign() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let verifier = VerifierStore::new(Delta::random(&mut rng));

    //     assert!(!verifier.wants_assign());
    // }

    // #[test]
    // fn test_store_prover_wants_assign_public() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut prover = ProverStore::default();

    //     let a = prover.alloc(128);

    //     prover
    //         .assign_public(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
    //         .unwrap();

    //     assert!(prover.wants_assign());
    // }

    // #[test]
    // fn test_store_prover_wants_assign_private() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut prover = ProverStore::default();

    //     let a = prover.alloc(128);

    //     prover
    //         .assign_private(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
    //         .unwrap();

    //     assert!(prover.wants_assign());
    // }

    // #[test]
    // fn test_store_prover_does_not_want_assign() {
    //     let prover = ProverStore::default();

    //     assert!(!prover.wants_assign());
    // }

    // #[test]
    // fn test_store_verifier_wants_decode() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     let a = verifier.alloc(128);
    //     _ = verifier.decode(a).unwrap();

    //     assert!(verifier.wants_verify_data());
    // }

    // #[test]
    // fn test_store_verifier_does_not_want_decode_uninit() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     _ = verifier.alloc(128);

    //     assert!(!verifier.wants_verify_data());
    // }

    // #[test]
    // fn test_store_prover_wants_decode() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut prover = ProverStore::default();
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     let a = verifier.alloc(128);
    //     _ = verifier.decode(a).unwrap();
    //     let payload = verifier.send_key_bits().unwrap();

    //     let a = prover.alloc(128);
    //     prover.set_macs(&[a], &[Block::default(); 128]).unwrap();
    //     prover.receive_key_bits(payload).unwrap();
    //     _ = prover.decode(a).unwrap();

    //     assert!(prover.wants_decode());
    // }

    // #[test]
    // fn test_store_prover_does_not_want_decode_uninit() {
    //     let mut prover = ProverStore::default();

    //     _ = prover.alloc(128);

    //     assert!(!prover.wants_decode());
    // }
}
