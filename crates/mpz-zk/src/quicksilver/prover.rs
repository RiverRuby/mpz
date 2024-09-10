use itybity::IntoBits;
use mpz_circuits::{types::Value, Circuit, CircuitError, Gate};
use mpz_common::{cpu::CpuBackend, Context};
use mpz_core::Block;
use mpz_ot::{RCOTReceiverOutput, RandomCOTReceiver};
use mpz_zk_core::quicksilver::{bools_to_bytes, Prover as ProverCore};
use serio::SinkExt;

use super::error::ProverError;

/// QuickSilver Prover.
pub struct Prover {
    macs: Vec<Block>,
    prover_core: ProverCore,
}

impl Prover {
    /// Create a new instance.
    pub fn new() -> Self {
        Self {
            macs: Vec::default(),
            prover_core: ProverCore::new(),
        }
    }
    /// Authenticate inputs.
    async fn auth_inputs<Ctx, RCOT>(
        &mut self,
        ctx: &mut Ctx,
        inputs: &[bool],
        rcot: &mut RCOT,
    ) -> Result<Vec<Block>, ProverError>
    where
        Ctx: Context,
        RCOT: RandomCOTReceiver<Ctx, bool, Block>,
    {
        let cot = rcot.receive_random_correlated(ctx, inputs.len()).await?;

        let (bits, macs) = self.prover_core.auth_input_bits(&inputs, cot)?;

        ctx.io_mut().send(bools_to_bytes(&bits)).await?;

        Ok(macs)
    }

    /// Prove.
    pub async fn prove<Ctx, RCOT>(
        &mut self,
        ctx: &mut Ctx,
        circ: &Circuit,
        input_value: impl Into<Value>,
        rcot: &mut RCOT,
    ) -> Result<(), ProverError>
    where
        Ctx: Context,
        RCOT: RandomCOTReceiver<Ctx, bool, Block>,
    {
        let len: usize = circ.inputs().iter().map(|v| v.len()).sum();

        let input_value = input_value.into().into_lsb0_vec();
        if input_value.len() != len {
            return Err(CircuitError::InvalidInputCount(len, input_value.len()))?;
        }

        if circ.feed_count() > self.macs.len() {
            self.macs.resize(circ.feed_count(), Default::default());
        }

        // Handle inputs.
        let input_macs = self.auth_inputs(ctx, &input_value, rcot).await?;

        for (mac, node) in input_macs
            .iter()
            .zip(circ.inputs().iter().flat_map(|v| v.iter()))
        {
            self.macs[node.id()] = *mac;
        }

        // Authenticate the circuit.
        while let Some(gate) = circ.gates().iter().next() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x_0 = self.macs[node_x.id()];
                    let y_0 = self.macs[node_y.id()];
                    self.macs[node_z.id()] = x_0 ^ y_0;
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    // Check the batched authenticated and gates.
                    if self.prover_core.enable_check() {
                        self.check_and_gates(ctx, rcot).await?;
                    }

                    let x_0 = self.macs[node_x.id()];
                    let y_0 = self.macs[node_y.id()];

                    let RCOTReceiverOutput {
                        choices: bit,
                        msgs: blk,
                        ..
                    } = rcot.receive_random_correlated(ctx, 1).await?;

                    let (d, z_0) = self.prover_core.auth_and_gate(x_0, y_0, (bit[0], blk[0]));

                    ctx.io_mut().send(d).await?;

                    self.macs[node_z.id()] = z_0;
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let x_0 = self.macs[node_x.id()];
                    self.macs[node_z.id()] = x_0 ^ Block::ONE;
                }
            }
        }

        // Handle final check.
        if self.prover_core.enable_final_check() {
            self.check_and_gates(ctx, rcot).await?;
        }

        // Handle outputs.
        let output_macs: Vec<Block> = circ
            .outputs()
            .iter()
            .flat_map(|v| v.iter())
            .map(|node| self.macs[node.id()])
            .collect();

        // Send the hash of the output macs.
        let hash = self.prover_core.finish(&output_macs);
        ctx.io_mut().send(hash).await?;

        Ok(())
    }

    // Check the and gates.
    async fn check_and_gates<Ctx, RCOT>(
        &mut self,
        ctx: &mut Ctx,
        rcot: &mut RCOT,
    ) -> Result<(), ProverError>
    where
        Ctx: Context,
        RCOT: RandomCOTReceiver<Ctx, bool, Block>,
    {
        let mut vope = crate::vope::receiver::Receiver::new();
        vope.setup()?;

        let v = vope.receive(ctx, rcot, 1).await?;

        let mut prover_core = std::mem::replace(&mut self.prover_core, ProverCore::default());

        let (u, prover_core) =
            CpuBackend::blocking(move || (prover_core.check_and_gates(v), prover_core)).await;

        // Send (U, V)
        ctx.io_mut().send(u).await?;

        self.prover_core = prover_core;
        Ok(())
    }
}
