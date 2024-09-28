use mpz_core::{
    bitvec::{BitSlice, BitVec},
    prg::Prg,
    Block,
};
use mpz_memory_core::{
    correlated::{Delta, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    AssignKind, Size, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use utils::{filter_drain::FilterDrain, range::RangeSet};

use crate::store::{AssignPayload, DecodePayload, MacPayload};

type Error = GeneratorStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct GeneratorStore {
    prg: Prg,
    key_store: KeyStore,
    data_store: BitStore,
    buffer_assign: Vec<AssignOp>,
    buffer_send_key_bits: Vec<Slice>,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl GeneratorStore {
    /// Creates a new generator store.
    pub fn new(seed: [u8; 16], delta: Delta) -> Self {
        Self {
            prg: Prg::new_with_seed(seed),
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            buffer_assign: Vec::new(),
            buffer_send_key_bits: Vec::new(),
            buffer_decode: Vec::new(),
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.key_store.delta()
    }

    /// Returns whether all the keys are set.
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

    /// Returns whether the store wants to send key bits.
    pub fn wants_send_key_bits(&self) -> bool {
        self.buffer_send_key_bits
            .iter()
            .any(|range| self.key_store.is_set(range.clone()))
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

    /// Allocates memory for a value.
    pub fn alloc(&mut self, len: usize) -> Slice {
        _ = self
            .key_store
            .alloc_with(&Block::random_vec(&mut self.prg, len));
        self.data_store.alloc(len)
    }

    /// Allocates uninitialized memory for output values of a circuit.
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

    /// Assigns private data.
    pub fn assign_private(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.data_store.try_set(slice, data)?;

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Private,
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

        self.buffer_send_key_bits.push(slice);
        self.buffer_decode.push(op);

        Ok(fut)
    }

    /// Executes assignment operations.
    ///
    /// Returns the payload to send to the evaluator as well as the keys to send using oblivious transfer.
    pub fn execute_assign(&mut self) -> Result<(AssignPayload, Vec<Block>)> {
        let mut idx_direct = Vec::new();
        let mut idx_oblivious = Vec::new();
        for op in self
            .buffer_assign
            .filter_drain(|op| self.key_store.is_set(op.slice))
        {
            match op.kind {
                AssignKind::Public | AssignKind::Private => {
                    idx_direct.push(op.slice);
                }
                AssignKind::Blind => {
                    idx_oblivious.push(op.slice);
                }
            }
        }

        let mut keys = Vec::new();
        for slice in &idx_oblivious {
            keys.extend_from_slice(self.key_store.oblivious_transfer(*slice)?);
        }

        let mut macs = Vec::new();
        for slice in &idx_direct {
            let data = self.data_store.try_get(*slice).expect("data should be set");
            macs.extend(self.key_store.authenticate(*slice, data)?);
        }

        Ok((
            AssignPayload {
                idx_direct: RangeSet::from(
                    idx_direct.into_iter().map(From::from).collect::<Vec<_>>(),
                ),
                idx_oblivious: RangeSet::from(
                    idx_oblivious
                        .into_iter()
                        .map(From::from)
                        .collect::<Vec<_>>(),
                ),
                macs,
            },
            keys,
        ))
    }

    pub fn send_key_bits(&mut self) -> Result<DecodePayload> {
        let mut idx = Vec::new();
        for slice in self
            .buffer_send_key_bits
            .filter_drain(|slice| self.key_store.is_set(*slice))
        {
            idx.push(slice);
        }

        let mut key_bits = BitVec::new();
        for slice in &idx {
            key_bits.extend(self.key_store.try_get_bits(*slice)?);
        }

        Ok(DecodePayload {
            idx: RangeSet::from(idx.into_iter().map(From::from).collect::<Vec<_>>()),
            key_bits,
        })
    }

    /// Verifies a proof of MACs from the evaluator.
    ///
    /// Resolves corresponding decode operations.
    pub fn verify_data(&mut self, payload: MacPayload) -> Result<()> {
        let MacPayload {
            idx,
            mut bits,
            proof,
        } = payload;

        self.key_store.verify(&idx, &mut bits, proof)?;

        let mut i = 0;
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.data_store.try_set(slice, &bits[i..i + slice.size()])?;
            i += slice.size();
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

/// Error for [`GeneratorStore`].
#[derive(Debug, thiserror::Error)]
#[error("generator store error: {}", .0)]
pub struct GeneratorStoreError(ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    KeyStore(KeyStoreError),
    #[error(transparent)]
    Store(StoreError),
}

impl From<KeyStoreError> for GeneratorStoreError {
    fn from(err: KeyStoreError) -> Self {
        Self(ErrorRepr::KeyStore(err))
    }
}

impl From<StoreError> for GeneratorStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}
