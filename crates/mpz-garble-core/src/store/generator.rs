use mpz_core::{
    bitvec::{BitSlice, BitVec},
    prg::Prg,
    Block,
};
use mpz_memory_core::{
    correlated::{Delta, SenderStore as Core, SenderStoreError as CoreError},
    AssignKind, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use rand::Rng;
use utils::{filter_drain::FilterDrain, range::RangeSet};

use crate::store::{AssignPayload, DecodePayload, MacPayload};

type Error = GeneratorStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct GeneratorStore {
    prg: Prg,
    inner: Core,
    buffer_assign: Vec<AssignOp>,
    buffer_send_key_bits: Vec<Slice>,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl GeneratorStore {
    /// Creates a new generator store.
    pub fn new(seed: [u8; 16], delta: Delta) -> Self {
        Self {
            prg: Prg::new_with_seed(seed),
            inner: Core::new(delta),
            buffer_assign: Vec::new(),
            buffer_send_key_bits: Vec::new(),
            buffer_decode: Vec::new(),
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.inner.delta()
    }

    /// Returns whether the keys are set for a slice.
    pub fn is_set_keys(&self, slice: Slice) -> bool {
        self.inner.is_set_keys(slice)
    }

    /// Returns whether the keys are assigned for a slice.
    pub fn is_assigned_keys(&self, slice: Slice) -> bool {
        self.inner.is_assigned_keys(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.inner.is_set_data(slice)
    }

    /// Returns whether the store wants to assign values.
    pub fn wants_assign(&self) -> bool {
        !self.buffer_assign.is_empty()
    }

    /// Returns whether the store wants to send key bits.
    pub fn wants_send_key_bits(&self) -> bool {
        self.buffer_send_key_bits
            .iter()
            .any(|slice| self.inner.is_set_keys(*slice))
    }

    /// Returns whether the store wants to verify data.
    pub fn wants_verify_data(&self) -> bool {
        self.buffer_decode
            .iter()
            .any(|op| self.inner.is_set_keys(op.slice))
    }

    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Block]> {
        self.inner.try_get_keys(slice).map_err(Error::from)
    }

    /// Allocates memory for a value.
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.inner.alloc_with_keys(len, || self.prg.gen())
    }

    /// Allocates uninitialized memory for output values of a circuit.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.inner.alloc(len)
    }

    /// Sets the output keys for a circuit.
    pub fn set_output(&mut self, slice: Slice, keys: &[Block]) -> Result<()> {
        self.inner.set_keys(&[slice], keys).map_err(Error::from)
    }

    /// Assigns public data.
    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.set_data(&[slice], &data)?;

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Public,
        });

        Ok(())
    }

    /// Assigns private data.
    pub fn assign_private(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.set_data(&[slice], &data)?;

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
            .filter_drain(|op| self.inner.is_set_keys(op.slice))
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

        let keys = self
            .inner
            .oblivious_transfer(idx_oblivious.iter().copied())?;
        let macs = self.inner.get_macs(idx_direct.iter().copied())?;

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
            .filter_drain(|slice| self.inner.is_set_keys(*slice))
        {
            idx.push(slice);
        }

        let key_bits = self.inner.key_bits(idx.iter().copied())?;

        Ok(DecodePayload {
            idx: RangeSet::from(idx.into_iter().map(From::from).collect::<Vec<_>>()),
            key_bits,
        })
    }

    /// Verifies a proof of MACs from the evaluator.
    ///
    /// Resolves corresponding decode operations.
    pub fn verify_data(&mut self, payload: MacPayload) -> Result<()> {
        let MacPayload { idx, bits, proof } = payload;

        let slices = idx
            .iter_ranges()
            .map(Slice::from_range_unchecked)
            .collect::<Vec<_>>();

        self.inner.verify(slices.iter().copied(), bits, proof)?;

        Ok(())
    }

    pub fn execute_decode(&mut self) -> Result<()> {
        for mut op in self
            .buffer_decode
            .filter_drain(|op| self.inner.is_set_data(op.slice))
        {
            let data = self
                .inner
                .try_get_data(op.slice)
                .expect("data should be set");
            op.send(data.to_bitvec()).unwrap();
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("generator store error")]
pub struct GeneratorStoreError {}

impl From<CoreError> for GeneratorStoreError {
    fn from(err: CoreError) -> Self {
        todo!()
    }
}
