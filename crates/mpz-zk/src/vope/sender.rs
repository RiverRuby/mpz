//! Implementation of VOPE sender

use crate::vope::error::SenderError;
use enum_try_as_inner::EnumTryAsInner;
use mpz_common::Context;
use mpz_core::Block;
use mpz_ot::{RCOTSenderOutput, RandomCOTSender, TransferId};
use mpz_zk_core::{
    vope::{
        sender::{state, Sender as SenderCore},
        CSP,
    },
    VOPESenderOutput,
};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
#[allow(missing_docs)]
pub enum State {
    Initialized(SenderCore<state::Initialized>),
    Extension(SenderCore<state::Extension>),
    Error,
}

/// VOPE sender (verifier)
#[derive(Debug)]
pub struct Sender {
    state: State,
    id: TransferId,
}

impl Sender {
    /// Creates a new Sender.
    pub fn new() -> Self {
        Self {
            state: State::Initialized(SenderCore::new()),
            id: TransferId::default(),
        }
    }

    /// Performs setup with the provided delta.
    ///
    /// # Arguments
    ///
    /// * `delta` - The delta value to use for VOPE extension.
    pub fn setup(&mut self, delta: Block) -> Result<(), SenderError> {
        let ext_sender = std::mem::replace(&mut self.state, State::Error).try_into_initialized()?;

        let ext_sender = ext_sender.setup(delta);

        self.state = State::Extension(ext_sender);

        Ok(())
    }

    /// Performs VOPE extension for sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The context.
    /// * `rcot` - The ideal random COT.
    /// * `d` - The polynomial degree.
    pub async fn send<Ctx, RCOT>(
        &mut self,
        ctx: &mut Ctx,
        rcot: &mut RCOT,
        d: usize,
    ) -> Result<VOPESenderOutput<Block>, SenderError>
    where
        Ctx: Context,
        RCOT: RandomCOTSender<Ctx, Block>,
    {
        let mut ext_sender =
            std::mem::replace(&mut self.state, State::Error).try_into_extension()?;

        assert!(d > 0);

        let RCOTSenderOutput { msgs: ks, .. } =
            rcot.send_random_correlated(ctx, (2 * d - 1) * CSP).await?;

        let (ext_sender, res) =
            Backend::spawn(move || ext_sender.extend(&ks, d).map(|res| (ext_sender, res))).await?;

        self.state = State::Extension(ext_sender);

        Ok(VOPESenderOutput {
            id: self.id.next_id(),
            eval: res,
        })
    }
}

impl Default for Sender {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
