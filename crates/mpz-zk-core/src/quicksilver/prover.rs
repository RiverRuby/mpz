use mpz_core::Block;
use mpz_ot_core::RCOTReceiverOutput;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use super::{bools_to_bytes, QsProverError, CHECK_BUFFER_SIZE};

/// Internal QuickSilver Prover.
#[derive(Debug, Default)]
pub struct Prover {
    /// Buffer for left wire label.
    buf_left: Vec<Block>,
    /// Buffer for right wire label.
    buf_right: Vec<Block>,
    /// Buffer for output wire label.
    buf_out: Vec<Block>,
    /// Counter for check.
    check_counter: usize,
    /// Hasher.
    hasher: blake3::Hasher,
    /// Hash buffer for the bools.
    buf_hash: Vec<bool>,
}

impl Prover {
    /// Create a new instance
    pub fn new() -> Self {
        Self {
            buf_left: vec![Block::ZERO; CHECK_BUFFER_SIZE],
            buf_right: vec![Block::ZERO; CHECK_BUFFER_SIZE],
            buf_out: vec![Block::ZERO; CHECK_BUFFER_SIZE],
            check_counter: 0,
            hasher: blake3::Hasher::new(),
            buf_hash: vec![false; CHECK_BUFFER_SIZE],
        }
    }

    /// Compute authenticated bits for inputs.
    /// See step 4 in Figure 5
    ///
    /// # Arguments
    ///
    /// * `inputs` - The input bits.
    /// * `cot` - The COT mask received from Ideal COT as the receiver.
    pub fn auth_input_bits(
        &mut self,
        inputs: &[bool],
        cot: RCOTReceiverOutput<bool, Block>,
    ) -> Result<(Vec<bool>, Vec<Block>), QsProverError> {
        if cot.choices.len() != inputs.len() {
            return Err(QsProverError(format!("lengths not match")));
        }

        let RCOTReceiverOutput {
            choices: bits,
            msgs: blks,
            ..
        } = cot;

        let res: (Vec<bool>, Vec<Block>) = bits
            .iter()
            .zip(inputs.iter())
            .zip(blks.iter())
            .map(|((mask, b), blk)| (b ^ mask, Self::set_value(*blk, *b)))
            .unzip();

        // Hash the bools.
        self.hasher.update(&bools_to_bytes(&res.0));

        Ok(res)
    }

    /// Compute authenticated and gate.
    /// See step 6 in Figure 5.
    ///
    /// # Arguments.
    ///
    /// * `ma` - The MAC of wire a.
    /// * `mb` - The MAC of wire b.
    /// * `cot` - The COT mask received from Ideal COT as the receiver.
    pub fn auth_and_gate(&mut self, ma: Block, mb: Block, cot: (bool, Block)) -> (bool, Block) {
        assert!(self.check_counter < CHECK_BUFFER_SIZE);

        self.buf_left[self.check_counter] = ma;
        self.buf_right[self.check_counter] = mb;

        let s = cot.0;
        let blk = cot.1;

        // Compute wa * wb
        let v = ma.lsb() & mb.lsb() == 1;
        // Compute the mask of v with s.
        let d = v ^ s;

        let mc = Self::set_value(blk, v);
        self.buf_out[self.check_counter] = mc;
        self.buf_hash[self.check_counter] = d;
        self.check_counter += 1;

        (d, mc)
    }

    /// Check and gate.
    /// See step 6, 7 in Figure 5.
    ///
    /// # Arguments.
    ///
    /// * `vope` - The mask blocks received from ideal VOPE.
    pub fn check_and_gates(&mut self, vope: (Block, Block)) -> (Block, Block) {
        assert!(self.check_counter <= CHECK_BUFFER_SIZE);
        cfg_if::cfg_if! {
            if #[cfg(feature = "rayon")]{
                let iter = self.buf_left[..self.check_counter]
                .par_iter()
                .zip(self.buf_right[..self.check_counter].par_iter())
                .zip(self.buf_out[..self.check_counter].par_iter());
            } else{
                let iter = self.buf_left[..self.check_counter]
                .iter()
                .zip(self.buf_right[..self.check_counter].iter())
                .zip(self.buf_out[..self.check_counter].iter())
            }
        }

        // Compute A0 and A1.
        let blocks: (Vec<Block>, Vec<Block>) = iter
            .map(|((a, b), c)| {
                let tmp0 = if a.lsb() == 1 { *b } else { Block::ZERO };
                let tmp1 = if b.lsb() == 1 { *a } else { Block::ZERO };

                (a.gfmul(*b), tmp0 ^ tmp1 ^ *c)
            })
            .unzip();

        // Compute chi and powers.
        self.hasher
            .update(&bools_to_bytes(&self.buf_hash[..self.check_counter]));
        let seed = *self.hasher.finalize().as_bytes();
        let seed = Block::try_from(&seed[0..16]).unwrap();
        let chis = Block::powers(seed, self.check_counter);

        // Compute the inner product.
        let u = Block::inn_prdt_red(&blocks.0, &chis);
        let v = Block::inn_prdt_red(&blocks.1, &chis);

        // Mask the results.
        let u = u ^ vope.0;
        let v = v ^ vope.1;

        // Update the hasher
        self.hasher.update(&u.to_bytes());
        self.hasher.update(&v.to_bytes());
        self.check_counter = 0;

        (u, v)
    }

    /// Enable and check or not.
    /// If the check_counter is set into the default number,
    /// we enable the check protocol.
    #[inline]
    pub fn enable_check(&self) -> bool {
        self.check_counter == CHECK_BUFFER_SIZE
    }

    // Set the LSB of the block to as the bit.
    // This assumes the lsb of delta is 1.
    #[inline]
    fn set_value(block: Block, b: bool) -> Block {
        (block & Block::MINIS_ONE) ^ (if b { Block::ONE } else { Block::ZERO })
    }
}
