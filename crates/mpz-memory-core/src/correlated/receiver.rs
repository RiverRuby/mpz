use blake3::Hash;
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use utils::range::{RangeSet, Subset, Union};

use crate::{Ptr, Size, Slice};

type Error = ReceiverStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct ReceiverStore {
    /// MACs.
    macs: Vec<Block>,
    /// MACs which are set.
    idx_set_macs: RangeSet<usize>,

    /// Pointer bits of the MAC keys.
    key_bits: BitVec,
    /// Key bits which are set.
    idx_set_key_bits: RangeSet<usize>,

    /// Plaintext data.
    data: BitVec,
    /// Data which are set.
    idx_set_data: RangeSet<usize>,
}

impl ReceiverStore {
    pub fn new() -> Self {
        Self {
            macs: Vec::new(),
            key_bits: BitVec::new(),
            data: BitVec::new(),
            idx_set_macs: RangeSet::default(),
            idx_set_key_bits: RangeSet::default(),
            idx_set_data: RangeSet::default(),
        }
    }
}

impl ReceiverStore {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            macs: Vec::with_capacity(capacity),
            key_bits: BitVec::with_capacity(capacity),
            data: BitVec::with_capacity(capacity),
            idx_set_macs: RangeSet::default(),
            idx_set_key_bits: RangeSet::default(),
            idx_set_data: RangeSet::default(),
        }
    }

    /// Returns whether the MACs are set.
    #[inline]
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.idx_set_macs)
    }

    /// Returns whether the key bits are set.
    #[inline]
    pub fn is_set_key_bits(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.idx_set_key_bits)
    }

    /// Returns whether the data are set.
    #[inline]
    pub fn is_set_data(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.idx_set_data)
    }

    #[inline]
    fn mark_set_macs(&mut self, slice: Slice) {
        self.idx_set_macs = self.idx_set_macs.union(&slice.to_range());
    }

    #[inline]
    fn mark_set_key_bits(&mut self, slice: Slice) {
        self.idx_set_key_bits = self.idx_set_key_bits.union(&slice.to_range());
    }

    #[inline]
    fn mark_set_data(&mut self, slice: Slice) {
        self.idx_set_data = self.idx_set_data.union(&slice.to_range());
    }

    /// Allocates uninitialized memory.
    pub fn alloc(&mut self, len: usize) -> Slice {
        let new_len = self.macs.len() + len;
        let slice = Slice::new_unchecked(Ptr::new(self.macs.len()), len);

        self.macs.resize_with(new_len, Default::default);
        self.key_bits.resize(new_len, false);
        self.data.resize(new_len, false);

        slice
    }

    /// Allocates memory with data and corresponding MACs.
    ///
    /// # Panics
    ///
    /// Panics if the length of the MACs is not equal to the length of the data.
    pub fn alloc_with(&mut self, data: &BitSlice, macs: &[Block]) -> Slice {
        assert_eq!(
            data.len(),
            macs.len(),
            "data length does not match MACs length"
        );

        let len = macs.len();
        let ptr = Ptr::new(self.macs.len());
        let slice = Slice::new_unchecked(ptr, len);

        let mut key_bits = data.to_bitvec();
        key_bits
            .iter_mut()
            .zip(data)
            .zip(macs)
            .for_each(|((mut key, data), mac)| {
                key.set(mac.lsb() ^ *data);
            });

        self.macs.extend_from_slice(macs);
        self.key_bits.extend_from_bitslice(&key_bits);
        self.data.extend_from_bitslice(data);

        self.mark_set_macs(slice);
        self.mark_set_key_bits(slice);
        self.mark_set_data(slice);

        slice
    }

    /// Sets MACs.
    ///
    /// Returns an error if the MACs are already set.
    pub fn set_macs(&mut self, slices: &[Slice], macs: &[Block]) -> Result<()> {
        let expected_len = slices.iter().map(|slice| slice.size()).sum::<usize>();
        if macs.len() != expected_len {
            todo!()
        }

        let mut idx = 0;
        for slice in slices.iter().copied() {
            let range = slice.to_range();

            if range.end > self.macs.len() {
                todo!()
            } else if self.is_set_macs(slice) {
                todo!()
            }

            self.macs[range].copy_from_slice(&macs[idx..idx + slice.size()]);
            self.mark_set_macs(slice);

            // Decode the MACs if the key bits are set and data is not set.
            if self.is_set_key_bits(slice) && !self.is_set_data(slice) {
                self.decode(slice);
            }

            idx += slice.size();
        }

        Ok(())
    }

    /// Sets key bits.
    ///
    /// Returns an error if the key bits are already set.
    pub fn set_key_bits(&mut self, slices: &[Slice], bits: &BitSlice) -> Result<()> {
        let expected_len = slices.iter().map(|slice| slice.size()).sum::<usize>();
        if bits.len() != expected_len {
            todo!()
        }

        let mut idx = 0;
        for slice in slices.iter().copied() {
            let range = slice.to_range();

            if range.end > self.key_bits.len() {
                todo!()
            } else if self.is_set_key_bits(slice) {
                todo!()
            }

            self.key_bits[range.clone()].copy_from_bitslice(&bits[idx..idx + slice.size()]);
            self.mark_set_key_bits(slice);

            // Decode the MACs if they are set and data is not set.
            if self.is_set_macs(slice) && !self.is_set_data(slice) {
                self.decode(slice);
            }

            idx += slice.size();
        }

        Ok(())
    }

    /// Sets plaintext data.
    ///
    /// Returns an error if the data is already set.
    pub fn set_data(&mut self, slices: &[Slice], data: &BitSlice) -> Result<()> {
        let expected_len = slices.iter().map(|slice| slice.size()).sum::<usize>();
        if data.len() != expected_len {
            todo!()
        }

        let mut idx = 0;
        for slice in slices.iter().copied() {
            let range = slice.to_range();

            if range.end > self.data.len() {
                todo!()
            } else if self.is_set_data(slice) {
                todo!()
            }

            self.data[range.clone()].copy_from_bitslice(&data[idx..idx + slice.size()]);
            self.mark_set_data(slice);

            // Decode the MACs if they are set and key bits are set.
            if self.is_set_macs(slice) && self.is_set_key_bits(slice) {
                self.decode(slice);
            }

            idx += slice.size();
        }

        Ok(())
    }

    /// Reads data from memory, returning an error if it is not set.
    pub fn try_get_data(&self, slice: Slice) -> Result<&BitSlice> {
        if !self.is_set_data(slice) {
            return Err(ErrorRepr::DataNotSet { slice }.into());
        }

        Ok(&self.data[slice.to_range()])
    }

    /// Reads MACs from memory, returning an error if they are not set.
    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Block]> {
        if !self.is_set_macs(slice) {
            todo!()
        }

        Ok(&self.macs[slice.to_range()])
    }

    /// Returns the pointer bits of the MACs and a proof of knowledge.
    pub fn prove(&self, slices: impl IntoIterator<Item = Slice>) -> Result<(BitVec, Hash)> {
        let mut hasher = blake3::Hasher::new();
        let mut bits = BitVec::new();
        for slice in slices {
            if !self.is_set_macs(slice) {
                todo!()
            }

            for mac in &self.macs[slice.to_range()] {
                bits.push(mac.lsb());
                hasher.update(&mac.to_bytes());
            }
        }

        Ok((bits, hasher.finalize()))
    }

    /// Decodes the MACs from the key bits.
    ///
    /// Caller must ensure that everything is ready and to not overwrite data.
    fn decode(&mut self, slice: Slice) {
        self.macs[slice.to_range()]
            .iter()
            .zip(&self.key_bits[slice.to_range()])
            .zip(&mut self.data[slice.to_range()])
            .for_each(|((mac, key_bit), mut bit)| {
                bit.set(mac.lsb() ^ *key_bit);
            });
        self.mark_set_data(slice);
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ReceiverStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("macs are already set for slice: {}", slice)]
    MacsAlreadySet { slice: Slice },
    #[error("key bits are already set for slice: {}", slice)]
    KeyBitsAlreadySet { slice: Slice },
    #[error("data is already set for slice: {}", slice)]
    DataAlreadySet { slice: Slice },
    #[error("data is not set for slice: {}", slice)]
    DataNotSet { slice: Slice },
}
