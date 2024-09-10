//! Implementation of VOPE receiver.

use crate::vope::error::ReceiverError;
use enum_try_as_inner::EnumTryAsInner;
use mpz_common::Context;
use mpz_core::Block;
use mpz_ot::{RCOTReceiverOutput, RandomCOTReceiver, TransferId};
use mpz_zk_core::{
    vope::{
        receiver::{state, Receiver as ReceiverCore},
        CSP,
    },
    VOPEReceiverOutput,
};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
#[allow(missing_docs)]
pub enum State {
    Initialized(ReceiverCore<state::Initialized>),
    Extension(ReceiverCore<state::Extension>),
    Error,
}

/// VOPE receiver (prover)
#[derive(Debug)]
pub struct Receiver {
    state: State,
    id: TransferId,
}

impl Receiver {
    /// Creates a new receiver.
    ///
    /// # Arguments
    ///
    /// * `rcot` - The random COT used by the receiver.
    pub fn new() -> Self {
        Self {
            state: State::Initialized(ReceiverCore::new()),
            id: TransferId::default(),
        }
    }

    /// Performs setup for receiver.
    pub fn setup(&mut self) -> Result<(), ReceiverError> {
        let ext_receiver =
            std::mem::replace(&mut self.state, State::Error).try_into_initialized()?;

        let ext_receiver = ext_receiver.setup();

        self.state = State::Extension(ext_receiver);

        Ok(())
    }

    /// Performs VOPE extension for receiver.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context.
    /// * `rcot` - The ideal random COT.
    /// * `d` - The polynomial degree.
    pub async fn receive<Ctx, RCOT>(
        &mut self,
        ctx: &mut Ctx,
        rcot: &mut RCOT,
        d: usize,
    ) -> Result<VOPEReceiverOutput<Block>, ReceiverError>
    where
        Ctx: Context,
        RCOT: RandomCOTReceiver<Ctx, bool, Block>,
    {
        let mut ext_receiver =
            std::mem::replace(&mut self.state, State::Error).try_into_extension()?;

        assert!(d > 0);

        let RCOTReceiverOutput {
            msgs: ms,
            choices: us,
            ..
        } = rcot
            .receive_random_correlated(ctx, (2 * d - 1) * CSP)
            .await?;

        // extend
        let (ext_receiver, res) = Backend::spawn(move || {
            ext_receiver
                .extend(&ms, &us, d)
                .map(|res| (ext_receiver, res))
        })
        .await?;

        self.state = State::Extension(ext_receiver);

        Ok(VOPEReceiverOutput {
            id: self.id.next_id(),
            coeff: res,
        })
    }
}
