use blake3::{Hash, Hasher};
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use utils::range::{Disjoint, Union};

use crate::{
    correlated::Delta,
    store::{Store, StoreError},
    RangeSet, Slice,
};

type Result<T> = core::result::Result<T, KeyStoreError>;

/// A linear store which manages correlated MAC keys.
#[derive(Debug, Clone)]
pub struct KeyStore {
    keys: Store<Block>,
    delta: Delta,
    used: RangeSet,
}

impl KeyStore {
    /// Creates a new key store.
    #[inline]
    pub fn new(delta: Delta) -> Self {
        Self {
            keys: Store::default(),
            delta,
            used: RangeSet::default(),
        }
    }

    /// Creates a new key store with the given capacity.
    #[inline]
    pub fn with_capacity(capacity: usize, delta: Delta) -> Self {
        Self {
            keys: Store::with_capacity(capacity),
            delta,
            used: RangeSet::default(),
        }
    }

    /// Returns the global correlation, `Δ`.
    #[inline]
    pub fn delta(&self) -> &Delta {
        &self.delta
    }

    /// Returns whether all the keys are set.
    #[inline]
    pub fn is_set(&self, slice: Slice) -> bool {
        self.keys.is_set(slice)
    }

    /// Returns whether any of the keys are used.
    #[inline]
    pub fn is_used(&self, slice: Slice) -> bool {
        !slice.to_range().is_disjoint(&self.used)
    }

    /// Allocates uninitialized memory.
    #[inline]
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.keys.alloc(len)
    }

    /// Allocates memory with the given keys.
    ///
    /// The provided keys are marked as used.
    #[inline]
    pub fn alloc_with(&mut self, keys: &[Block]) -> Slice {
        self.keys.alloc_with(keys)
    }

    /// Returns keys if they are set.
    ///
    /// # Safety
    ///
    /// **Never** use this method to transfer MACs to the receiver.
    ///
    /// Use [`authenticate`](Self::authenticate) or [`oblivious_transfer`](Self::oblivious_transfer) instead.
    #[inline]
    pub fn try_get(&self, slice: Slice) -> Result<&[Block]> {
        self.keys.try_get(slice).map_err(From::from)
    }

    /// Sets keys, returning an error if the keys are already set.
    #[inline]
    pub fn try_set(&mut self, slice: Slice, keys: &[Block]) -> Result<()> {
        self.keys.try_set(slice, keys).map_err(From::from)
    }

    /// Returns the pointer bits of the keys if they are set.
    pub fn try_get_bits(&self, slice: Slice) -> Result<impl Iterator<Item = bool> + '_> {
        self.keys
            .try_get(slice)
            .map(|keys| keys.iter().map(|key| key.lsb()))
            .map_err(From::from)
    }

    /// Authenticates the data, returning MACs.
    ///
    /// Returns an error if the keys are already used.
    ///
    /// # Panics
    ///
    /// Panics if the bit slice is not the same length as the slice.
    pub fn authenticate<'a>(
        &'a mut self,
        slice: Slice,
        data: &'a BitSlice,
    ) -> Result<impl Iterator<Item = Block> + 'a> {
        assert_eq!(
            slice.size,
            data.len(),
            "bits are not the same length as the slice"
        );

        if self.is_used(slice) {
            return Err(KeyStoreError::AlreadyAssigned(slice));
        } else if !self.keys.is_set(slice) {
            return Err(KeyStoreError::Uninit(slice));
        }

        let range = slice.to_range();
        self.used = self.used.union(&range);

        Ok(data
            .iter()
            .zip(self.keys.try_get(slice).expect("keys should be set"))
            .map(|(bit, key)| {
                if *bit {
                    key ^ self.delta.as_block()
                } else {
                    key ^ &Block::ZERO
                }
            }))
    }

    /// Returns the keys to send using oblivious transfer.
    ///
    /// Returns an error if the keys are already used.
    pub fn oblivious_transfer(&mut self, slice: Slice) -> Result<&[Block]> {
        if self.is_used(slice) {
            return Err(KeyStoreError::AlreadyAssigned(slice));
        } else if !self.keys.is_set(slice) {
            return Err(KeyStoreError::Uninit(slice));
        }

        let keys = self.keys.try_get(slice).expect("keys should be set");
        self.used = self.used.union(&slice.to_range());

        Ok(keys)
    }

    /// Adjusts the keys for the given range.
    ///
    /// # Panics
    ///
    /// Panics if the bit slice is not the same length as the range.
    pub fn adjust(&mut self, slice: Slice, adjust: &BitSlice) -> Result<()> {
        assert_eq!(
            slice.size,
            adjust.len(),
            "bits are not the same length as the slice"
        );

        self.keys
            .try_get_slice_mut(slice)?
            .iter_mut()
            .zip(adjust)
            .for_each(|(key, bit)| {
                key.xor_lsb(*bit);
            });

        Ok(())
    }

    /// Verifies MACs, writing authenticated data back into the provided bit slice.
    ///
    /// # Panics
    ///
    /// Panics if the ranges and bits are not the same length.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Ranges of the MACs.
    /// * `bits` - MAC pointer bits.
    /// * `proof` - Hash which proves knowledge of the MACs.
    pub fn verify(&self, ranges: &RangeSet, bits: &mut BitSlice, proof: Hash) -> Result<()> {
        assert_eq!(
            ranges.len(),
            bits.len(),
            "ranges and bits are not the same length"
        );

        let mut data = BitVec::with_capacity(bits.len());
        let mut hasher = Hasher::new();
        let mut idx = 0;
        for range in ranges.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.keys
                .try_get(slice)?
                .iter()
                .zip(&bits[idx..idx + slice.size])
                .for_each(|(key, mac_bit)| {
                    let value = key.lsb() ^ *mac_bit;
                    let expected_mac = key
                        ^ if value {
                            self.delta.as_block()
                        } else {
                            &Block::ZERO
                        };

                    data.push(value);
                    hasher.update(&expected_mac.to_bytes());
                });
            idx += slice.size;
        }

        if hasher.finalize() != proof {
            return Err(KeyStoreError::Verify);
        }

        bits.copy_from_bitslice(&data);

        Ok(())
    }
}

/// Error for [`KeyStore`].
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("invalid slice: {}", .0)]
    InvalidSlice(Slice),
    #[error("keys are not initialized: {}", .0)]
    Uninit(Slice),
    #[error("keys are already set: {}", .0)]
    AlreadySet(Slice),
    #[error("keys are already assigned: {}", .0)]
    AlreadyAssigned(Slice),
    #[error("MAC verification error")]
    Verify,
}

impl From<StoreError> for KeyStoreError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::InvalidSlice(slice) => Self::InvalidSlice(slice),
            StoreError::Uninit(slice) => Self::Uninit(slice),
            StoreError::AlreadySet(slice) => Self::AlreadySet(slice),
        }
    }
}
