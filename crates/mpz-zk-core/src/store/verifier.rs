use std::mem;

use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_memory_core::{
    correlated::{Delta, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    AssignKind, Size, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use utils::filter_drain::FilterDrain;

use crate::store::{AssignPayload, DecodePayload, MacPayload};

type Error = VerifierStoreError;
type Result<T> = core::result::Result<T, Error>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug)]
pub struct VerifierStore {
    key_store: KeyStore,
    data_store: BitStore,
    buffer_assign: Vec<AssignOp>,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl VerifierStore {
    /// Creates a new verifier store.
    pub fn new(delta: Delta) -> Self {
        Self {
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            buffer_assign: Vec::new(),
            buffer_decode: Vec::new(),
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.key_store.delta()
    }

    /// Returns whether the keys are set for a slice.
    pub fn is_set_keys(&self, slice: Slice) -> bool {
        self.key_store.is_set(slice)
    }

    /// Returns whether the keys are assigned for a slice.
    pub fn is_assigned_keys(&self, slice: Slice) -> bool {
        self.key_store.is_used(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.data_store.is_set(slice)
    }

    /// Returns whether the store wants to assign values.
    pub fn wants_assign(&self) -> bool {
        !self.buffer_assign.is_empty()
    }

    /// Returns whether the store wants to verify data.
    pub fn wants_verify_data(&self) -> bool {
        self.buffer_decode
            .iter()
            .any(|op| self.key_store.is_set(op.slice))
    }

    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Block]> {
        self.key_store.try_get(slice).map_err(Error::from)
    }

    /// Allocates memory.
    pub fn alloc_with(&mut self, keys: &[Block]) -> Slice {
        self.key_store.alloc_with(keys);
        self.data_store.alloc(keys.len())
    }

    /// Allocates uninitialized memory for outputs of a circuit.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.key_store.alloc(len);
        self.data_store.alloc(len)
    }

    /// Sets the output keys for a circuit.
    pub fn set_output(&mut self, slice: Slice, keys: &[Block]) -> Result<()> {
        self.key_store.try_set(slice, keys).map_err(Error::from)
    }

    /// Assigns public data.
    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.data_store.try_set(slice, data)?;

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Public,
        });

        Ok(())
    }

    /// Assigns blind data.
    pub fn assign_blind(&mut self, slice: Slice) -> Result<()> {
        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Blind,
        });

        Ok(())
    }

    /// Buffers a decoding operation, returning a future which will resolve to the value when it is ready.
    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        let (fut, op) = DecodeFuture::new(slice);

        self.buffer_decode.push(op);

        Ok(fut)
    }

    /// Executes assignment operations.
    ///
    /// Returns the payload to send to the prover as well as the keys to send using oblivious transfer.
    pub fn execute_assign(&mut self, payload: AssignPayload) -> Result<()> {
        let mut ops = mem::take(&mut self.buffer_assign);
        ops.sort_by_key(|op| op.slice.ptr());

        let mut idx = Vec::new();
        for op in ops {
            match op.kind {
                AssignKind::Public | AssignKind::Blind => {
                    idx.push(op.slice.to_range());
                }
                AssignKind::Private => unreachable!("private data can not be assigned"),
            }
        }

        let idx_expected = RangeSet::from(idx);

        let AssignPayload { idx, adjust } = payload;

        if idx != idx_expected {
            todo!()
        }

        let mut i = 0;
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.key_store.adjust(slice, &adjust[i..i + slice.size()])?;
            i += slice.size();
        }

        Ok(())
    }

    /// Verifies a proof of MACs from the prover.
    ///
    /// Resolves corresponding decode operations.
    pub fn verify_data(&mut self, payload: MacPayload) -> Result<()> {
        let MacPayload {
            idx,
            mut bits,
            proof,
        } = payload;

        self.key_store.verify(&idx, &mut bits, proof)?;

        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.data_store.try_set(slice, &bits)?;
        }

        Ok(())
    }

    pub fn execute_decode(&mut self) -> Result<()> {
        for mut op in self
            .buffer_decode
            .filter_drain(|op| self.data_store.is_set(op.slice))
        {
            let data = self
                .data_store
                .try_get(op.slice)
                .expect("data should be set");
            op.send(data.to_bitvec()).unwrap();
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("verifier store error")]
pub struct VerifierStoreError {}

impl From<KeyStoreError> for VerifierStoreError {
    fn from(err: KeyStoreError) -> Self {
        todo!()
    }
}

impl From<StoreError> for VerifierStoreError {
    fn from(err: StoreError) -> Self {
        todo!()
    }
}
