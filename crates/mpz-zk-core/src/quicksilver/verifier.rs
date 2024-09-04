use mpz_core::Block;
use mpz_ot_core::RCOTSenderOutput;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use super::{bools_to_bytes, QsVerifierError, CHECK_BUFFER_SIZE};

/// QuickSilver Verifier.
#[derive(Debug)]
pub struct Verifier {
    /// Global secret.
    delta: Block,
    /// Buffer for left wire label.
    buf_left: Vec<Block>,
    /// Buffer for right wire label.
    buf_right: Vec<Block>,
    /// Buffer for output wire label.
    buf_out: Vec<Block>,
    /// Counter for check.
    counter: usize,
    /// Hasher.
    hasher: blake3::Hasher,
    /// Hash buffer for the bools.
    buf_hash: Vec<bool>,
    /// Indicate the and_gate check passes or not.
    and_gate_checked: bool,
}

impl Verifier {
    /// Create a new instance
    ///
    /// # Arguments.
    ///
    /// * `delta` - The global secret.
    pub fn new(delta: Block) -> Self {
        Self {
            delta,
            buf_left: vec![Block::ZERO; CHECK_BUFFER_SIZE],
            buf_right: vec![Block::ZERO; CHECK_BUFFER_SIZE],
            buf_out: vec![Block::ZERO; CHECK_BUFFER_SIZE],
            counter: 0,
            hasher: blake3::Hasher::new(),
            buf_hash: vec![false; CHECK_BUFFER_SIZE],
            and_gate_checked: true,
        }
    }
    /// Compute authenticated bits for inputs.
    /// See step 4 in Figure 5
    /// # Arguments
    ///
    /// * `masks` - The mask bits sent from the prover.
    /// * `cot` - The COT mask received from Ideal COT as the sender.
    pub fn compute_input_bits(
        &mut self,
        masks: &[bool],
        cot: RCOTSenderOutput<Block>,
        // The mask bits sent by prover.
    ) -> Result<Vec<Block>, QsVerifierError> {
        if masks.len() != cot.msgs.len() {
            return Err(QsVerifierError::InvalidInputs);
        }

        // Hash the bools.
        self.hasher.update(&bools_to_bytes(masks));

        let RCOTSenderOutput { msgs: blks, .. } = cot;

        let res = blks
            .iter()
            .zip(masks.iter())
            .map(|(blk, mask)| {
                let block = *blk ^ (if *mask { self.delta } else { Block::ZERO });
                Self::set_zero(block)
            })
            .collect();

        Ok(res)
    }

    /// Compute authenticated and gate.
    /// See step 6 in Figure 5.
    ///
    /// # Arguments.
    ///
    /// * `ka` - The KEY of wire a.
    /// * `kb` - The KEY of wire b.
    /// * `mask` - The mask sent by the prover.
    /// * `cot` - The COT mask received from Ideal COT as the sender.
    pub fn compute_and_gate(
        &mut self,
        ka: Block,
        kb: Block,
        mask: bool,
        cot: RCOTSenderOutput<Block>,
    ) -> Result<(), QsVerifierError> {
        if cot.msgs.len() != 1 {
            return Err(QsVerifierError::InvalidInputs);
        }

        assert!(self.counter < CHECK_BUFFER_SIZE);

        self.buf_left[self.counter] = ka;
        self.buf_right[self.counter] = kb;
        self.buf_hash[self.counter] = mask;

        let RCOTSenderOutput { msgs: blks, .. } = cot;

        let block = blks[0] ^ if mask { self.delta } else { Block::ZERO };
        self.buf_out[self.counter] = Self::set_zero(block);
        self.counter += 1;

        Ok(())
    }

    /// Check and gate.
    /// See step 6, 7 in Figure 5.
    ///
    /// # Arguments.
    ///
    /// * `vope` - The mask block received from ideal VOPE.
    /// * `u` - The block sent by the prover.
    /// * `v` - The block sent by the prover.
    pub fn check_and_gate(&mut self, vope: Block, u: Block, v: Block) {
        assert!(self.counter <= CHECK_BUFFER_SIZE);
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")]{
                let iter = self.buf_left[..self.counter]
                .par_iter()
                .zip(self.buf_right[..self.counter].par_iter())
                .zip(self.buf_out[..self.counter].par_iter());
            } else{
                let iter = self.buf_left[..self.counter]
                .iter()
                .zip(self.buf_right[..self.counter].iter())
                .zip(self.buf_out[..self.counter].iter())
            }
        }

        // Compute B.
        let block: Vec<Block> = iter
            .map(|((a, b), c)| a.gfmul(*b) ^ c.gfmul(self.delta))
            .collect();

        // Compute chi and powers.
        self.hasher
            .update(&bools_to_bytes(&self.buf_hash[..=self.counter]));
        let seed = *self.hasher.finalize().as_bytes();
        let seed = Block::try_from(&seed[0..16]).unwrap();
        let chis = Block::powers(seed, self.counter);

        // Compute the inner product.
        let w = Block::inn_prdt_red(&block, &chis);
        self.and_gate_checked &= (w ^ vope) == u ^ v.gfmul(self.delta);

        self.hasher.update(&u.to_bytes());
        self.hasher.update(&v.to_bytes());
        self.counter = 0;
    }

    /// Returns the and_check results.
    pub fn checked(&self) -> bool {
        self.and_gate_checked
    }

    // Set the lsb of the block to zero.
    // This assumes the lsb of delta is 1.
    #[inline]
    fn set_zero(block: Block) -> Block {
        block & Block::MINIS_ONE
    }
}
