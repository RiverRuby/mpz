use mpz_core::{hash::Hash, serialize::CanonicalSerialize, utils::blake3, Block};
use mpz_ot_core::RCOTSenderOutput;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::VOPESenderOutput;

use super::{bools_to_bytes, QsVerifierError, CHECK_BUFFER_SIZE};

/// QuickSilver Verifier.
#[derive(Debug, Default)]
pub struct Verifier {
    /// Global secret.
    delta: Block,
    /// Buffer for left wire KEY.
    buf_left: Vec<Block>,
    /// Buffer for right wire KEY.
    buf_right: Vec<Block>,
    /// Buffer for output wire KEY.
    buf_out: Vec<Block>,
    /// Counter for check.
    check_counter: usize,
    /// Hasher.
    hasher: blake3::Hasher,
    /// Hash buffer for the bools.
    buf_hash: Vec<bool>,
    /// Indicate the checks pass or not.
    checked: bool,
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
            check_counter: 0,
            hasher: blake3::Hasher::new(),
            buf_hash: vec![false; CHECK_BUFFER_SIZE],
            checked: true,
        }
    }
    /// Compute authenticated bits for inputs.
    /// See step 4 in Figure 5
    /// # Arguments
    ///
    /// * `masks` - The mask bits sent from the prover.
    /// * `cot` - The COT mask received from Ideal COT as the sender.
    pub fn auth_input_bits(
        &mut self,
        masks: &[bool],
        cot: RCOTSenderOutput<Block>,
        // The mask bits sent by prover.
    ) -> Result<Vec<Block>, QsVerifierError> {
        if masks.len() != cot.msgs.len() {
            return Err(QsVerifierError(format!("lengths not match")));
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
    pub fn auth_and_gate(&mut self, ka: Block, kb: Block, mask: bool, cot: Block) -> Block {
        assert!(self.check_counter < CHECK_BUFFER_SIZE);

        self.buf_left[self.check_counter] = ka;
        self.buf_right[self.check_counter] = kb;
        self.buf_hash[self.check_counter] = mask;

        let block = cot ^ if mask { self.delta } else { Block::ZERO };
        let kc = Self::set_zero(block);
        self.buf_out[self.check_counter] = kc;
        self.check_counter += 1;

        kc
    }

    /// Check and gate.
    /// See step 6, 7 in Figure 5.
    ///
    /// # Arguments.
    ///
    /// * `vope` - The mask block received from ideal VOPE.
    /// * `u` - The block sent by the prover.
    /// * `v` - The block sent by the prover.
    pub fn check_and_gates(&mut self, vope: VOPESenderOutput<Block>, u: Block, v: Block) {
        assert!(self.check_counter <= CHECK_BUFFER_SIZE);
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")]{
                let iter = self.buf_left[..self.check_counter]
                .par_iter()
                .zip(self.buf_right[..self.check_counter].par_iter())
                .zip(self.buf_out[..self.check_counter].par_iter());
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
            .update(&bools_to_bytes(&self.buf_hash[..=self.check_counter]));
        let seed = *self.hasher.finalize().as_bytes();
        let seed = Block::try_from(&seed[0..16]).unwrap();
        let chis = Block::powers(seed, self.check_counter);

        // Compute the inner product.
        let w = Block::inn_prdt_red(&block, &chis);
        self.checked &= (w ^ vope.eval) == u ^ v.gfmul(self.delta);

        self.hasher.update(&u.to_bytes());
        self.hasher.update(&v.to_bytes());
        self.check_counter = 0;
    }

    /// Enable and check or not.
    /// If check_counter is set to the default buffer size,
    /// we enable the check protocol.
    #[inline]
    pub fn enable_check(&self) -> bool {
        self.check_counter == CHECK_BUFFER_SIZE
    }

    /// Enable the final check or not.
    /// if check_counter is zero, then no need to check.
    #[inline]
    pub fn enable_final_check(&self) -> bool {
        self.check_counter != 0
    }

    /// Hash the output keys with the outputs.
    pub fn finish(
        &mut self,
        hash: Hash,
        keys: &[Block],
        outputs: &[bool],
    ) -> Result<(), QsVerifierError> {
        if keys.len() != outputs.len() {
            return Err(QsVerifierError(format!("lengths not match")));
        }

        let pre_hash: Vec<Block> = keys
            .iter()
            .zip(outputs.iter())
            .map(|(&k, &o)| if o { k ^ self.delta } else { k })
            .collect();

        let expected_hash = Hash::from(blake3(&pre_hash.to_bytes()));
        self.checked &= hash == expected_hash;

        Ok(())
    }

    /// Returns the and_check results.
    #[inline]
    pub fn checked(&self) -> bool {
        self.checked
    }

    /// Returns delta.
    pub fn delta(&self) -> Block {
        self.delta
    }

    // Set the lsb of the block to zero.
    // This assumes the lsb of delta is 1.
    #[inline]
    fn set_zero(block: Block) -> Block {
        block & Block::MINIS_ONE
    }
}
