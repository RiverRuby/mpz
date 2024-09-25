use blake3::{Hash, Hasher};
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use utils::range::{Disjoint, Subset, Union};

use crate::{correlated::Delta, AssignKind, Ptr, Size, Slice};

type Error = SenderStoreError;
type Result<T> = core::result::Result<T, Error>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug)]
pub struct SenderStore {
    /// MAC keys.
    keys: Vec<Block>,
    /// Global correlation, `Δ`.
    delta: Delta,
    /// Keys which have been initialized.
    initialized: RangeSet,
    /// Keys which have been assigned.
    assigned: RangeSet,

    /// Plaintext data.
    data: BitVec,
    /// Data which has been authenticated.
    auth: RangeSet,
}

impl SenderStore {
    pub fn new(delta: Delta) -> Self {
        Self {
            keys: Vec::new(),
            delta,
            initialized: RangeSet::default(),
            assigned: RangeSet::default(),
            data: BitVec::new(),
            auth: RangeSet::default(),
        }
    }

    /// Returns the global correlation, `Δ`.
    pub fn delta(&self) -> &Delta {
        &self.delta
    }
}

impl SenderStore {
    /// Creates a new sender store with a given capacity.
    pub fn with_capacity(capacity: usize, delta: Delta) -> Self {
        Self {
            keys: Vec::with_capacity(capacity),
            delta,
            initialized: RangeSet::default(),
            assigned: RangeSet::default(),
            data: BitVec::with_capacity(capacity),
            auth: RangeSet::default(),
        }
    }

    #[inline]
    fn set_initialized(&mut self, slice: Slice) {
        self.initialized = self.initialized.union(&slice.to_range());
    }

    #[inline]
    fn set_assigned(&mut self, slice: Slice) {
        self.assigned = self.assigned.union(&slice.to_range());
    }

    #[inline]
    fn set_auth(&mut self, slice: Slice) {
        self.auth = self.auth.union(&slice.to_range());
    }

    /// Returns whether the keys are set.
    #[inline]
    pub fn is_set_keys(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.initialized)
    }

    /// Returns whether the keys are assigned.
    #[inline]
    pub fn is_assigned_keys(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.assigned)
    }

    /// Returns whether the data is set.
    #[inline]
    pub fn is_set_data(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.auth)
    }

    /// Allocates uninitialized memory.
    pub fn alloc(&mut self, len: usize) -> Slice {
        let slice = Slice::new_unchecked(Ptr::new(self.keys.len()), len);
        let new_len: usize = self.keys.len() + len;

        self.keys.resize_with(new_len, Default::default);
        self.data.resize(new_len, false);

        slice
    }

    /// Allocates memory, initializing the keys.
    pub fn alloc_with_keys(&mut self, len: usize, init_keys: impl FnMut() -> Block) -> Slice {
        let slice = Slice::new_unchecked(Ptr::new(self.keys.len()), len);
        let new_len: usize = self.keys.len() + len;

        self.keys.resize_with(new_len, init_keys);
        self.data.resize(new_len, false);

        self.set_initialized(slice);

        slice
    }

    /// Sets MAC keys, marking them as initialized.
    ///
    /// Returns an error if the keys are already initialized.
    pub fn set_keys(&mut self, slices: &[Slice], keys: &[Block]) -> Result<()> {
        let expected_len = slices.iter().map(Size::size).sum();
        if keys.len() != expected_len {
            todo!()
        }

        let mut idx = 0;
        for slice in slices {
            if self.is_set_keys(*slice) {
                todo!()
            }

            self.keys[slice.to_range()].copy_from_slice(&keys[idx..idx + slice.size()]);
            self.set_initialized(*slice);

            idx += slice.size();
        }

        Ok(())
    }

    /// Sets data, marking it as authenticated.
    ///
    /// Returns an error if the data is already set.
    pub fn set_data(&mut self, slices: &[Slice], data: &BitSlice) -> Result<()> {
        let expected_len = slices.iter().map(Size::size).sum();
        if data.len() != expected_len {
            todo!()
        }

        let mut idx = 0;
        for slice in slices {
            if self.is_set_data(*slice) {
                todo!()
            } else if self.is_assigned_keys(*slice) {
                todo!("keys are already assigned, must use verify")
            }

            self.data[slice.to_range()].copy_from_bitslice(&data[idx..idx + slice.size()]);
            self.set_assigned(*slice);
            self.set_auth(*slice);

            idx += slice.size();
        }

        Ok(())
    }

    /// Returns MACs for the given slices.
    pub fn get_macs(&self, slices: impl IntoIterator<Item = Slice>) -> Result<Vec<Block>> {
        let mut macs = Vec::new();
        for slice in slices {
            if !self.is_set_data(slice) {
                todo!()
            }

            macs.extend(
                self.keys[slice.to_range()]
                    .into_iter()
                    .zip(&self.data[slice.to_range()])
                    .map(|(key, bit)| {
                        key ^ if *bit {
                            self.delta.as_block()
                        } else {
                            &Block::ZERO
                        }
                    }),
            );
        }

        Ok(macs)
    }

    /// Reads data from memory.
    ///
    /// Returns an error if the data is not authenticated.
    pub fn try_get_data(&self, slice: Slice) -> Result<&BitSlice> {
        if !self.is_set_data(slice) {
            todo!()
        }

        Ok(&self.data[slice.to_range()])
    }

    /// Reads keys from memory.
    ///
    /// Returns an error if the keys are not set.
    ///
    /// # Safety
    ///
    /// Never use this method to transfer MACs to the receiver. Instead, use [`oblivious_transfer`](Self::oblivious_transfer).
    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Block]> {
        if !self.is_set_keys(slice) {
            todo!()
        }

        Ok(&self.keys[slice.to_range()])
    }

    /// Returns keys to send to the receiver using correlated oblivious transfer.
    pub fn oblivious_transfer(
        &mut self,
        slices: impl IntoIterator<Item = Slice>,
    ) -> Result<Vec<Block>> {
        let mut keys = Vec::new();
        for slice in slices {
            if !self.is_set_keys(slice) {
                todo!("keys are not initialized")
            } else if self.is_assigned_keys(slice) {
                todo!("keys are already assigned")
            }

            keys.extend_from_slice(&self.keys[slice.to_range()]);
            self.set_assigned(slice);
        }

        Ok(keys)
    }

    /// Returns the pointer bits of the keys.
    pub fn key_bits(&self, slices: impl IntoIterator<Item = Slice>) -> Result<BitVec> {
        let mut bits = BitVec::new();

        for slice in slices {
            if !self.is_set_keys(slice) {
                todo!("keys are not initialized")
            }

            self.keys[slice.to_range()].iter().for_each(|key| {
                bits.push(key.lsb());
            });
        }

        Ok(bits)
    }

    /// Adjusts the keys using the given adjustment bits.
    ///
    /// This is used to derandomize a slice after the receiver has made its choice.
    ///
    /// # Arguments
    ///
    /// * `slice` - Memory reference.
    /// * `adjust` - Adjustment bits.
    pub fn adjust(&mut self, slice: Slice, adjust: impl IntoIterator<Item = bool>) -> Result<()> {
        todo!()
    }

    /// Verifies a proof of data.
    ///
    /// # Arguments
    ///
    /// * `slices` - The slices which are being proven.
    /// * `bits` - Pointer bits of the MACs.
    /// * `proof` - Hash proof of knowledge of the MACs.
    pub fn verify(
        &mut self,
        slices: impl IntoIterator<Item = Slice>,
        mut bits: BitVec,
        proof: Hash,
    ) -> Result<()> {
        let mut decoded = Vec::new();
        let mut hasher = Hasher::new();
        let mut idx = 0;

        // Decode the MAC bits and verify the proof. We reuse the `bits` allocation
        // to store the authenticated bits.
        for slice in slices {
            if !self.is_set_keys(slice) {
                todo!()
            }

            self.keys[slice.to_range()]
                .iter()
                .zip(&mut bits[idx..idx + slice.size()])
                .for_each(|(key, mut bit)| {
                    let truth = key.lsb() ^ *bit;
                    let mac = key
                        ^ if truth {
                            self.delta.as_block()
                        } else {
                            &Block::ZERO
                        };

                    bit.set(truth);
                    hasher.update(&mac.to_bytes());
                });

            // If we have already authenticated the data, then assert it matches.
            if self.is_set_data(slice)
                && &self.data[slice.to_range()] != &bits[idx..idx + slice.size()]
            {
                todo!()
            }

            decoded.push(slice);
            idx += slice.size();
        }

        if hasher.finalize() != proof {
            todo!()
        }

        // Write authenticated bits into memory after verification.
        idx = 0;
        decoded.into_iter().for_each(|slice| {
            self.data[slice.to_range()].copy_from_bitslice(&bits[idx..idx + slice.size()]);
            self.set_auth(slice);
            idx += slice.size();
        });

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("sender store error")]
pub struct SenderStoreError {}

impl SenderStoreError {
    pub fn store<E>(err: E) -> Self {
        todo!()
    }
}
