use blake3::{Hash, Hasher};
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};

use crate::{
    store::{Store, StoreError},
    RangeSet, Slice,
};

type Result<T> = core::result::Result<T, MacStoreError>;

/// A linear store which manages correlated MACs.
#[derive(Debug, Clone, Default)]
pub struct MacStore {
    macs: Store<Block>,
}

impl MacStore {
    /// Creates a new MAC store.
    #[inline]
    pub fn new() -> Self {
        Self {
            macs: Store::default(),
        }
    }

    /// Creates a new MAC store with the given capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            macs: Store::with_capacity(capacity),
        }
    }

    /// Returns whether all the MACs are set.
    #[inline]
    pub fn is_set(&self, slice: Slice) -> bool {
        self.macs.is_set(slice)
    }

    /// Allocates uninitialized memory.
    #[inline]
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.macs.alloc(len)
    }

    /// Allocates memory with the given MACs.
    #[inline]
    pub fn alloc_with(&mut self, macs: &[Block]) -> Slice {
        self.macs.alloc_with(macs)
    }

    /// Returns MACs if they are set.
    #[inline]
    pub fn try_get(&self, slice: Slice) -> Result<&[Block]> {
        self.macs.try_get(slice).map_err(From::from)
    }

    /// Sets MACs, returning an error if they are already set.
    #[inline]
    pub fn try_set(&mut self, slice: Slice, macs: &[Block]) -> Result<()> {
        self.macs.try_set(slice, macs).map_err(From::from)
    }

    /// Returns the pointer bits of the MACs if they are set.
    pub fn try_get_bits(&self, slice: Slice) -> Result<impl Iterator<Item = bool> + '_> {
        self.macs
            .try_get(slice)
            .map(|macs| macs.iter().map(|mac| mac.lsb()))
            .map_err(From::from)
    }

    /// Adjusts the MACs for the given range.
    ///
    /// # Panics
    ///
    /// Panics if the bit slice is not the same length as the range.
    pub fn try_adjust(&mut self, slice: Slice, adjust: &BitSlice) -> Result<()> {
        assert_eq!(
            slice.size,
            adjust.len(),
            "bit slice is not the same length as the range"
        );

        self.macs
            .try_get_slice_mut(slice)?
            .iter_mut()
            .zip(adjust)
            .for_each(|(mac, bit)| {
                mac.xor_lsb(*bit);
            });

        Ok(())
    }

    /// Proves MACs.
    ///
    /// # Arguments
    ///
    /// * `ranges` - Ranges to prove.
    pub fn prove(&self, ranges: &RangeSet) -> Result<(BitVec, Hash)> {
        let mut bits = BitVec::with_capacity(ranges.len());
        let mut hasher = Hasher::new();
        for range in ranges.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.macs.try_get(slice)?.iter().for_each(|mac| {
                bits.push(mac.lsb());
                hasher.update(&mac.to_bytes());
            });
        }

        Ok((bits, hasher.finalize()))
    }
}

/// Error for [`MacStore`].
#[derive(Debug, thiserror::Error)]
pub enum MacStoreError {
    #[error("invalid slice: {}", .0)]
    InvalidSlice(Slice),
    #[error("MACs are not initialized: {}", .0)]
    Uninit(Slice),
    #[error("MACs are already set: {}", .0)]
    AlreadySet(Slice),
    #[error("MACs are already assigned: {}", .0)]
    AlreadyAssigned(Slice),
    #[error("MAC verification error")]
    Verify,
}

impl From<StoreError> for MacStoreError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::InvalidSlice(slice) => Self::InvalidSlice(slice),
            StoreError::Uninit(slice) => Self::Uninit(slice),
            StoreError::AlreadySet(slice) => Self::AlreadySet(slice),
        }
    }
}
