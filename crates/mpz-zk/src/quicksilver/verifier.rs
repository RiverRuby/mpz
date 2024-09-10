use itybity::IntoBits;
use mpz_circuits::{types::Value, Circuit, CircuitError, Gate};
use mpz_common::{cpu::CpuBackend, Context};
use mpz_core::Block;
use mpz_ot::{RCOTSenderOutput, RandomCOTSender};
use mpz_zk_core::quicksilver::{bytes_to_bools, Verifier as VerifierCore};
use serio::stream::IoStreamExt;

use super::error::VerifierError;

/// QuickSilver Verifier.
pub struct Verifier {
    keys: Vec<Block>,
    verifier_core: VerifierCore,
}

impl Verifier {
    /// Create a new instance.
    pub fn new(delta: Block) -> Self {
        Self {
            keys: Vec::default(),
            verifier_core: VerifierCore::new(delta),
        }
    }

    /// Authenticate inputs.
    async fn auth_inputs<Ctx, RCOT>(
        &mut self,
        len: usize,
        ctx: &mut Ctx,
        rcot: &mut RCOT,
    ) -> Result<Vec<Block>, VerifierError>
    where
        Ctx: Context,
        RCOT: RandomCOTSender<Ctx, Block>,
    {
        let cot = rcot.send_random_correlated(ctx, len).await?;

        let bytes: Vec<u8> = ctx.io_mut().expect_next().await?;

        let masks = bytes_to_bools(&bytes);
        assert_eq!(masks.len(), len);

        let blks = self.verifier_core.auth_input_bits(&masks, cot)?;

        Ok(blks)
    }

    /// Verify
    pub async fn verify<Ctx, RCOT>(
        &mut self,
        ctx: &mut Ctx,
        circ: &Circuit,
        output_value: impl Into<Value>,
        rcot: &mut RCOT,
    ) -> Result<(), VerifierError>
    where
        Ctx: Context,
        RCOT: RandomCOTSender<Ctx, Block>,
    {
        let len: usize = circ.outputs().iter().map(|v| v.len()).sum();
        let output_value = output_value.into().into_lsb0_vec();
        if output_value.len() != len {
            return Err(CircuitError::InvalidOutputCount(len, output_value.len()))?;
        }

        if circ.feed_count() > self.keys.len() {
            self.keys.resize(circ.feed_count(), Default::default());
        }

        let input_len: usize = circ.inputs().iter().map(|v| v.len()).sum();
        // Handle inputs.
        let input_keys = self.auth_inputs(input_len, ctx, rcot).await?;

        for (key, node) in input_keys
            .iter()
            .zip(circ.inputs().iter().flat_map(|v| v.iter()))
        {
            self.keys[node.id()] = *key;
        }

        // Authenticate the circuit.
        while let Some(gate) = circ.gates().iter().next() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x_0 = self.keys[node_x.id()];
                    let y_0 = self.keys[node_y.id()];
                    self.keys[node_z.id()] = x_0 ^ y_0;
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    // Check the batched authenticated and gats.
                    if self.verifier_core.enable_check() {
                        self.check_and_gates(ctx, rcot).await?;
                    }

                    let x_0 = self.keys[node_x.id()];
                    let y_0 = self.keys[node_y.id()];

                    let RCOTSenderOutput { msgs: blk, .. } =
                        rcot.send_random_correlated(ctx, 1).await?;

                    let mask = ctx.io_mut().expect_next().await?;
                    let z_0 = self.verifier_core.auth_and_gate(x_0, y_0, mask, blk[0]);

                    self.keys[node_z.id()] = z_0;
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x_0 = self.keys[node_x.id()];
                    self.keys[node_z.id()] = x_0 ^ self.verifier_core.delta() ^ Block::ONE;
                }
            }
        }

        // Handle final check.
        if self.verifier_core.enable_final_check() {
            self.check_and_gates(ctx, rcot).await?;
        }

        // Handle outputs.
        let output_keys: Vec<Block> = circ
            .outputs()
            .iter()
            .flat_map(|v| v.iter())
            .map(|node| self.keys[node.id()])
            .collect();

        let hash = ctx.io_mut().expect_next().await?;
        self.verifier_core
            .finish(hash, &output_keys, &output_value)?;

        Ok(())
    }

    // Check the and gates.
    async fn check_and_gates<Ctx, RCOT>(
        &mut self,
        ctx: &mut Ctx,
        rcot: &mut RCOT,
    ) -> Result<(), VerifierError>
    where
        Ctx: Context,
        RCOT: RandomCOTSender<Ctx, Block>,
    {
        let mut vope = crate::vope::sender::Sender::new();
        vope.setup(self.verifier_core.delta())?;

        let v = vope.send(ctx, rcot, 1).await?;

        let u: (Block, Block) = ctx.io_mut().expect_next().await?;

        let mut verifier_core = std::mem::replace(&mut self.verifier_core, VerifierCore::default());

        let (_, verifier_core) = CpuBackend::blocking(move || {
            (verifier_core.check_and_gates(v, u.0, u.1), verifier_core)
        })
        .await;

        self.verifier_core = verifier_core;
        Ok(())
    }

    /// Returns checked over not.
    #[inline]
    pub fn checked(&self) -> bool {
        self.verifier_core.checked()
    }
}
