//! Correlated memory store.
//!
//! This module provides a memory store for protocols which use authenticated MACs with a linear correlation structure:
//!
//! `M = k + x * Δ`
//!
//! Where `k` is a random key, `x` is the authenticated value, and `Δ` is a global correlation value referred to as delta.
//!
//! One party, the Sender, holds the key `k` and delta `Δ`. The other party, the Receiver, holds the MAC `M`.
//!
//! `M` can be viewed as a MAC on `x` which can be verified by the Sender by checking the relation above holds.
//!
//! # Fields
//!
//! At the moment we only support the binary field, where the MACs and keys are in the extension field `GF(2^128)`.
//!
//! # Pointer bit
//!
//! The least significant bit of the keys and delta `Δ` is used as a pointer bit. This bit encodes the truth value of
//! the MAC `M` in the following way:
//!
//! The pointer bit of delta `Δ` is fixed to 1, which ensures the relation `LSB(M) = LSB(k) ^ x` is present. With this,
//! the value `x` can be recovered easily given only 1 bit of the MAC `M` and of the key `k`.
//!
//! Note that `k` is sampled uniformly at random, so its pointer bit can be viewed as a one-time pad on `x`. A Receiver
//! presented with a MAC `M` alone learns nothing about `x`.
//!
//! Notice also that this can be viewed as an additive secret sharing of the value `x`, where the Sender holds
//! `LSB(k)` and the Receiver holds `LSB(M)` such that `x = LSB(k) ^ LSB(M)`.
//!
//! # Derandomization
//!
//! During the offline-phase, the Sender and Receiver can compute MACs on random values provided by the
//! Receiver and later derandomize them.
//!
//! For example, given a MAC `M = k + r * Δ` where `r` is a random value known only to the Receiver, the Receiver can obtain a
//! MAC on the value `x` by sending `d = x ^ r`.
//!
//! The Sender then adjusts their key `k` by computing `k = k + d * Δ` and sets `LSB(k) = 0`.
//!
//! The Receiver adjusts their MAC by setting `LSB(M) = x`.
//!
//! In the end, the relationships hold `M = k + x * Δ` and `LSB(M) = LSB(k) ^ x`.

mod keys;
mod macs;

use std::ops::BitXor;

pub use keys::{KeyStore, KeyStoreError};
pub use macs::{MacStore, MacStoreError};

use mpz_core::Block;
use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delta(Block);

impl Delta {
    /// Creates a new Delta, setting the pointer bit to 1.
    #[inline]
    pub fn new(mut value: Block) -> Self {
        value.set_lsb(true);
        Self(value)
    }

    /// Generate a random block using the provided RNG
    #[inline]
    pub fn random<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self::new(rng.gen())
    }

    /// Returns the inner block
    #[inline]
    pub fn as_block(&self) -> &Block {
        &self.0
    }

    /// Returns the inner block
    #[inline]
    pub fn into_inner(self) -> Block {
        self.0
    }
}

impl Distribution<Delta> for Standard {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Delta {
        Delta::new(self.sample(rng))
    }
}

impl Into<Block> for Delta {
    fn into(self) -> Block {
        self.0
    }
}

impl AsRef<Block> for Delta {
    fn as_ref(&self) -> &Block {
        &self.0
    }
}

impl BitXor<Block> for Delta {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: Block) -> Block {
        self.0 ^ rhs
    }
}

impl BitXor<Delta> for Block {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: Delta) -> Block {
        self ^ rhs.0
    }
}

impl BitXor<Block> for &Delta {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: Block) -> Block {
        self.0 ^ rhs
    }
}

impl BitXor<&Block> for Delta {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: &Block) -> Block {
        self.0 ^ rhs
    }
}

impl BitXor<&Delta> for Block {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: &Delta) -> Block {
        self ^ rhs.0
    }
}

impl BitXor<Delta> for &Block {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: Delta) -> Block {
        self ^ rhs.0
    }
}

impl BitXor<&Delta> for &Block {
    type Output = Block;

    #[inline]
    fn bitxor(self, rhs: &Delta) -> Block {
        self ^ rhs.0
    }
}

#[cfg(test)]
mod tests {
    use mpz_ot_core::{ideal::cot::IdealCOT, COTReceiverOutput};
    use rand::{rngs::StdRng, SeedableRng};

    use crate::Slice;

    use super::*;

    type BitVec = mpz_core::bitvec::BitVec<u32>;

    #[test]
    fn test_correlated_store() {
        let mut cot = IdealCOT::default();
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        cot.set_delta(delta.into_inner());

        let mut keys = KeyStore::new(delta);
        let mut macs = MacStore::default();

        let val_a = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let val_b = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

        let ref_a_keys = keys.alloc_with(&Block::random_vec(&mut rng, 128));
        let ref_b_keys = keys.alloc_with(&Block::random_vec(&mut rng, 128));

        let ref_a_macs = macs.alloc(128);
        let ref_b_macs = macs.alloc(128);

        let macs_a = keys
            .authenticate(ref_a_keys, &val_a)
            .unwrap()
            .collect::<Vec<_>>();
        let keys_b = keys.oblivious_transfer(ref_b_keys).unwrap().to_vec();

        let (_, COTReceiverOutput { msgs: macs_b, .. }) =
            cot.correlated(keys_b, val_b.iter().by_vals().collect());

        macs.try_set(ref_a_macs, &macs_a).unwrap();
        macs.try_set(ref_b_macs, &macs_b).unwrap();

        assert!(keys.is_set(ref_a_keys));
        assert!(keys.is_set(ref_b_keys));
        assert!(macs.is_set(ref_a_macs));
        assert!(macs.is_set(ref_b_macs));

        let key_bits_a = BitVec::from_iter(keys.try_get_bits(ref_a_keys).unwrap());
        let key_bits_b = BitVec::from_iter(keys.try_get_bits(ref_b_keys).unwrap());

        let mac_bits_a = BitVec::from_iter(macs.try_get_bits(ref_a_macs).unwrap());
        let mac_bits_b = BitVec::from_iter(macs.try_get_bits(ref_b_macs).unwrap());

        let val_a_recovered = key_bits_a ^ mac_bits_a;
        let val_b_recovered = key_bits_b ^ mac_bits_b;

        assert_eq!(val_a, val_a_recovered);
        assert_eq!(val_b, val_b_recovered);

        let (mut bits, hash) = macs
            .prove(&Slice::to_rangeset([ref_a_macs, ref_b_macs]))
            .unwrap();

        keys.verify(
            &Slice::to_rangeset([ref_a_keys, ref_b_keys]),
            &mut bits,
            hash,
        )
        .unwrap();

        assert_eq!(&val_a, &bits[0..128]);
        assert_eq!(&val_b, &bits[128..]);
    }
}
