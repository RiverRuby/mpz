use blake3::Hasher;
use mpz_circuits::{Circuit, Gate};
use mpz_core::Block;
use mpz_memory_core::correlated::Delta;

type GateIter<'a> = std::slice::Iter<'a, Gate>;
type Result<T> = core::result::Result<T, VerifierError>;

pub struct Verifier {
    keys: Vec<Block>,

    buffer_b: Vec<Block>,
    transcript_hash: Hasher,
}

impl Verifier {
    pub fn execute(
        &mut self,
        circ: &Circuit,
        inputs: &[Block],
        gates: &[Block],
    ) -> Result<VerifierConsumer<'_, GateIter<'_>>> {
        todo!()
    }
}

pub struct VerifierConsumer<'a, I> {
    keys: &'a mut [Block],
    delta: Delta,
    gates: I,
    counter: usize,
    and_count: usize,
    complete: bool,

    buffer_b: &'a mut Vec<Block>,
    transcript_hash: &'a mut Hasher,
}

impl<'a, I> VerifierConsumer<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if the evaluator wants more encrypted gates.
    #[inline]
    pub fn wants_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Processes the next gate in the circuit.
    #[inline]
    pub fn next(&mut self, mask: bool) {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = self.keys[node_x.id()];
                    let y = self.keys[node_y.id()];
                    self.keys[node_z.id()] = x ^ y;
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let key_x = &self.keys[node_x.id()];
                    let key_y = &self.keys[node_y.id()];
                    let key_z = &mut self.keys[node_z.id()];

                    if mask {
                        *key_z = *key_z ^ self.delta.as_block();
                    } else {
                        *key_z = *key_z ^ &Block::ZERO;
                    };

                    self.counter += 1;

                    // If we have more AND gates to evaluate, return.
                    if self.wants_gates() {
                        return;
                    }
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x = self.keys[node_x.id()];
                    self.keys[node_z.id()] = x;
                }
            }
        }

        self.complete = true;
    }
}

#[derive(Debug, thiserror::Error)]
#[error("verifier error")]
pub struct VerifierError {}
