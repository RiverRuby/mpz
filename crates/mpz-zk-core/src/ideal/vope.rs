//! Ideal VOPE functionality.

use mpz_core::{prg::Prg, Block};
use mpz_ot_core::TransferId;
use rand_core::SeedableRng;

use crate::{VOPEReceiverOutput, VOPESenderOutput};

/// The ideal VOPE functionality.
#[derive(Debug)]
pub struct IdealVOPE {
    delta: Block,
    transfer_id: TransferId,
    counter: usize,
    prg: Prg,
}

impl IdealVOPE {
    /// Creates a new ideal VOPE functionality.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed for the PRG.
    /// * `delta` - The correlation.
    pub fn new(seed: Block, delta: Block) -> Self {
        Self {
            delta,
            transfer_id: TransferId::default(),
            counter: 0,
            prg: Prg::from_seed(seed),
        }
    }

    /// Returns the correlation, delta.
    pub fn delta(&self) -> Block {
        self.delta
    }

    /// Sets the correlation, delta.
    pub fn set_delta(&mut self, delta: Block) {
        self.delta = delta;
    }

    /// Returns the current transfer id.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Returns the number of VOPE executed.
    pub fn count(&self) -> usize {
        self.counter
    }

    /// Executes the VOPE.
    ///
    /// # Arguments
    ///
    /// * `degree` - The degree of the polynomnial.
    pub fn random_correlated(
        &mut self,
        degree: usize,
    ) -> (VOPESenderOutput<Block>, VOPEReceiverOutput<Block>) {
        let mut coeff = vec![Block::ZERO; degree + 1];
        self.prg.random_blocks(&mut coeff);

        let powers = Block::powers(self.delta, degree + 1);

        let eval = Block::inn_prdt_red(&coeff, &powers);

        self.counter += 1;
        let id = self.transfer_id.next_id();

        (
            VOPESenderOutput { id, eval },
            VOPEReceiverOutput { id, coeff },
        )
    }
}

impl Default for IdealVOPE {
    fn default() -> Self {
        let mut rng = Prg::from_seed(Block::ZERO);
        Self::new(rng.random_block(), rng.random_block())
    }
}

#[cfg(test)]
mod tests {
    use crate::{test::poly_check, VOPEReceiverOutput, VOPESenderOutput};

    use super::IdealVOPE;

    #[test]
    fn test_ideal_vope() {
        let mut ideal = IdealVOPE::default();

        let (VOPESenderOutput { eval, .. }, VOPEReceiverOutput { coeff, .. }) =
            ideal.random_correlated(10);

        assert!(poly_check(&coeff, eval, ideal.delta()));
    }
}
