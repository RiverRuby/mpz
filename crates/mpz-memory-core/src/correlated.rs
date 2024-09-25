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
//! `LSB(k)` and the Receiver holds `LSB(M)` such that `x = LSB(k) + LSB(M)`.

mod receiver;
mod sender;

use std::ops::BitXor;

pub use receiver::{ReceiverStore, ReceiverStoreError};
pub use sender::{SenderStore, SenderStoreError};

use mpz_core::Block;
use rand::{distributions::Standard, prelude::Distribution, CryptoRng, Rng};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delta(Block);

impl Delta {
    /// Creates a new Delta, setting the pointer bit to 1.
    #[inline]
    pub fn new(mut value: Block) -> Self {
        value.set_lsb();
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
    use mpz_core::bitvec::BitVec;
    use mpz_ot_core::{ideal::cot::IdealCOT, COTReceiverOutput};

    use super::*;

    #[test]
    fn test_correlated_store() {
        let mut cot = IdealCOT::default();
        let mut rng = rand::thread_rng();
        let delta = Delta::random(&mut rng);
        cot.set_delta(delta.into_inner());

        let mut sender = SenderStore::new(delta);
        let mut receiver = ReceiverStore::default();

        let val_a = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let val_b = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

        let ref_a_sender = sender.alloc_with_keys(128, || rng.gen());
        let ref_b_sender = sender.alloc_with_keys(128, || rng.gen());

        let ref_a_receiver = receiver.alloc(128);
        let ref_b_receiver = receiver.alloc(128);

        sender.set_data(&[ref_a_sender], &val_a).unwrap();

        let macs_a = sender.get_macs([ref_a_sender]).unwrap();
        let keys_b = sender.oblivious_transfer([ref_b_sender]).unwrap();

        let (_, COTReceiverOutput { msgs: macs_b, .. }) =
            cot.correlated(keys_b, val_b.iter().by_vals().collect());

        receiver.set_macs(&[ref_a_receiver], &macs_a).unwrap();
        receiver.set_macs(&[ref_b_receiver], &macs_b).unwrap();

        assert!(sender.is_set_keys(ref_a_sender));
        assert!(sender.is_set_keys(ref_b_sender));
        assert!(receiver.is_set_macs(ref_a_receiver));
        assert!(receiver.is_set_macs(ref_b_receiver));

        let key_bits = sender.key_bits([ref_a_sender, ref_b_sender]).unwrap();
        receiver
            .set_key_bits(&[ref_a_receiver, ref_b_receiver], &key_bits)
            .unwrap();

        let (mac_bits, hash) = receiver.prove([ref_a_receiver, ref_b_receiver]).unwrap();
        sender
            .verify([ref_a_sender, ref_b_sender], mac_bits, hash)
            .unwrap();

        assert_eq!(sender.try_get_data(ref_a_sender).unwrap(), &val_a);
        assert_eq!(sender.try_get_data(ref_b_sender).unwrap(), &val_b);
        assert_eq!(receiver.try_get_data(ref_a_receiver).unwrap(), &val_a);
        assert_eq!(receiver.try_get_data(ref_b_receiver).unwrap(), &val_b);
    }
}
