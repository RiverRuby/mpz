use std::mem;

use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_memory_core::{
    correlated::{ReceiverStore as Core, ReceiverStoreError as CoreError},
    AssignKind, Size, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Union},
};

use crate::store::{AssignPayload, DecodePayload, MacPayload};

type Error = EvaluatorStoreError;
type Result<T> = core::result::Result<T, Error>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug, Default)]
pub struct EvaluatorStore {
    inner: Core,
    buffer_assign: Vec<AssignOp>,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl EvaluatorStore {
    /// Allocates uninitialized memory for a value.
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.inner.alloc(len)
    }

    /// Returns whether the MACs are set for a slice.
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        self.inner.is_set_macs(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.inner.is_set_data(slice)
    }

    pub fn wants_assign(&self) -> bool {
        !self.buffer_assign.is_empty()
    }

    pub fn wants_key_bits(&self) -> bool {
        self.buffer_decode
            .iter()
            .any(|op| !self.inner.is_set_key_bits(op.slice) && self.inner.is_set_macs(op.slice))
    }

    pub fn wants_decode(&self) -> bool {
        self.buffer_decode
            .iter()
            .any(|op| self.inner.is_set_key_bits(op.slice) && self.inner.is_set_macs(op.slice))
    }

    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Block]> {
        self.inner.try_get_macs(slice).map_err(Error::from)
    }

    pub fn set_macs(&mut self, slices: &[Slice], macs: &[Block]) -> Result<()> {
        self.inner.set_macs(slices, macs).map_err(Error::from)
    }

    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.set_data(&[slice], data)?;

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Public,
        });

        Ok(())
    }

    pub fn assign_private(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.set_data(&[slice], data)?;

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Private,
        });

        Ok(())
    }

    pub fn assign_blind(&mut self, slice: Slice) -> Result<()> {
        if self.inner.is_set_macs(slice) {
            todo!("slice already assigned")
        }

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Blind,
        });

        Ok(())
    }

    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        let (fut, op) = DecodeFuture::new(slice);

        self.buffer_decode.push(op);

        Ok(fut)
    }

    /// Executes assignment operations.
    ///
    /// Returns a receiver for the assignment payload and the choices for oblivious transfer.
    pub fn execute_assign(&mut self) -> Result<(ReceiveAssign<'_>, Vec<bool>)> {
        let mut direct = Vec::new();
        let mut oblivious = Vec::new();
        let mut choices = Vec::new();
        for op in mem::take(&mut self.buffer_assign) {
            match op.kind {
                AssignKind::Public | AssignKind::Blind => {
                    direct.push(op.slice);
                }
                AssignKind::Private => {
                    oblivious.push(op.slice);
                    choices.extend(
                        self.inner
                            .try_get_data(op.slice)
                            .expect("data should be set")
                            .into_iter()
                            .map(|bit| *bit),
                    );
                }
            }
        }

        Ok((
            ReceiveAssign {
                store: self,
                direct,
                oblivious,
            },
            choices,
        ))
    }

    /// Receives key bits from the generator.
    pub fn receive_key_bits(&mut self, payload: DecodePayload) -> Result<()> {
        let DecodePayload { idx, key_bits } = payload;

        let slices = idx
            .iter_ranges()
            .map(Slice::from_range_unchecked)
            .collect::<Vec<_>>();

        self.inner.set_key_bits(&slices, &key_bits)?;

        Ok(())
    }

    /// Executes ready decode operations.
    ///
    /// Returns MAC proof to send to the generator.
    pub fn execute_decode(&mut self) -> Result<MacPayload> {
        let slices = self
            .buffer_decode
            .filter_drain(|op| {
                if let Ok(data) = self.inner.try_get_data(op.slice) {
                    op.send(data.to_bitvec()).unwrap();
                    true
                } else {
                    false
                }
            })
            .map(|op| op.slice)
            .collect::<Vec<_>>();

        let (bits, proof) = self.inner.prove(slices.iter().copied())?;

        Ok(MacPayload {
            idx: RangeSet::from(slices.into_iter().map(From::from).collect::<Vec<_>>()),
            bits,
            proof,
        })
    }
}

#[must_use]
pub struct ReceiveAssign<'a> {
    store: &'a mut EvaluatorStore,
    direct: Vec<Slice>,
    oblivious: Vec<Slice>,
}

impl ReceiveAssign<'_> {
    /// Receives the MACs from the generator.
    ///
    /// # Arguments
    ///
    /// * `payload` - Assignment payload.
    /// * `oblivious` - MACs received via oblivious transfer.
    pub fn receive(self, payload: AssignPayload, oblivious_macs: Vec<Block>) -> Result<()> {
        let AssignPayload {
            idx_direct: direct,
            idx_oblivious: oblivious,
            macs,
        } = payload;

        let expected_direct = RangeSet::from(
            self.direct
                .iter()
                .map(|slice| slice.to_range())
                .collect::<Vec<_>>(),
        );

        let expected_oblivious = RangeSet::from(
            self.oblivious
                .iter()
                .map(|slice| slice.to_range())
                .collect::<Vec<_>>(),
        );

        if direct != expected_direct {
            todo!()
        } else if oblivious != expected_oblivious {
            todo!()
        }

        self.store.inner.set_macs(&self.direct, &macs)?;
        self.store
            .inner
            .set_macs(&self.oblivious, &oblivious_macs)?;

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("evaluator store error")]
pub struct EvaluatorStoreError {}

impl From<CoreError> for EvaluatorStoreError {
    fn from(err: CoreError) -> Self {
        todo!()
    }
}
