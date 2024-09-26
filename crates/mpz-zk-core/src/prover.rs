use blake3::Hasher;
use mpz_circuits::{Circuit, Gate};
use mpz_core::Block;

type Result<T> = core::result::Result<T, ProverError>;

pub struct Prover {
    masks: Vec<bool>,
    macs: Vec<Block>,
    counter: usize,
    transcript_hash: Hasher,
}

impl Prover {
    pub fn execute(
        &mut self,
        circ: &Circuit,
        inputs: &[Block],
        masks: &[bool],
        gates: &[Block],
    ) -> Result<ProverIter<'_, std::slice::Iter<'_, Gate>>> {
        todo!()
    }
}

pub struct ProverIter<'a, I> {
    witness: &'a mut [bool],
    macs: &'a mut [Block],
    gates: I,
    counter: usize,
    and_count: usize,
    complete: bool,
    transcript_hash: &'a mut Hasher,
}

impl<'a, I> ProverIter<'a, I> {
    /// Returns `true` if there are more gates to process.
    #[inline]
    pub fn has_gates(&self) -> bool {
        self.counter != self.and_count
    }
}

impl<'a, I> Iterator for ProverIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor { x, y, z } => {
                    let mac_x = self.macs[x.id()];
                    let mac_y = self.macs[y.id()];
                    self.macs[z.id()] = mac_x ^ mac_y;
                }
                Gate::And { x, y, z } => {
                    let w_x = self.witness[x.id()];
                    let w_y = self.witness[y.id()];
                    let w_z = w_x & w_y;

                    let d = self.witness[z.id()] ^ w_z;
                    self.witness[z.id()] = w_z;

                    self.macs[z.id()].xor_lsb(d);

                    // If we have processed all AND gates, we can compute
                    // the rest of the "free" gates.
                    if !self.has_gates() {
                        assert!(self.next().is_none());

                        self.complete = true;
                    }

                    return Some(d);
                }
                Gate::Inv { x, z } => {
                    let mut mac = self.macs[x.id()];
                    mac.xor_lsb(true);
                    self.macs[z.id()] = mac;
                }
            }
        }

        None
    }
}

#[derive(Debug, thiserror::Error)]
#[error("prover error")]
pub struct ProverError {}
