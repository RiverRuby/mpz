//! An implementation of the [`Ferret`](https://eprint.iacr.org/2020/924.pdf) protocol.
mod error;
mod mpcot;
mod receiver;
mod sender;
mod spcot;

pub use error::{ReceiverError, SenderError};
pub use receiver::Receiver;
pub use sender::Sender;

use mpz_core::lpn::LpnParameters;
use mpz_ot_core::ferret::LpnType;

/// Configuration of Ferret.
#[derive(Debug, Clone)]
pub struct FerretConfig {
    lpn_parameters: LpnParameters,
    lpn_type: LpnType,
}

impl FerretConfig {
    /// Create a new instance.
    ///
    /// # Arguments.
    ///
    /// * `lpn_parameters` - The parameters of LPN.
    /// * `lpn_type` - The type of LPN.
    pub fn new(lpn_parameters: LpnParameters, lpn_type: LpnType) -> Self {
        Self {
            lpn_parameters,
            lpn_type,
        }
    }

    /// Get the lpn type
    pub fn lpn_type(&self) -> LpnType {
        self.lpn_type
    }

    /// Get the lpn parameters
    pub fn lpn_parameters(&self) -> LpnParameters {
        self.lpn_parameters
    }
}

/// Ferret config with regular LPN parameters.
/// Parameters for setup with small extension output.
pub const FERRET_REGULAR_SETUP_SMALL: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 102_400,
        k: 6_750,
        t: 1_600,
    },
    lpn_type: LpnType::Regular,
};

/// Ferret config with regular LPN parameters.
/// Parameters for extension with small extension output.
pub const FERRET_REGULAR_EXTENSION_SMALL: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 1_740_800,
        k: 66_400,
        t: 1700,
    },
    lpn_type: LpnType::Regular,
};

/// Ferret config with regular LPN parameters.
/// Parameters for setup with medium extension output.
pub const FERRET_REGULAR_SETUP_MEDIUM: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 283_648,
        k: 18_584,
        t: 1_108,
    },
    lpn_type: LpnType::Regular,
};

/// Ferret config with regular LPN parameters.
/// Parameters for extension with medium extension output.
pub const FERRET_REGULAR_EXTENSION_MEDIUM: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 5_324_800,
        k: 240_000,
        t: 1_300,
    },
    lpn_type: LpnType::Regular,
};

/// Ferret config with regular LPN parameters.
/// Parameters for setup with large extension output.
pub const FERRET_REGULAR_SETUP_LARGE: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 518_656,
        k: 34_643,
        t: 1_013,
    },
    lpn_type: LpnType::Regular,
};

/// Ferret config with regular LPN parameters.
/// Parameters for extension with large extension output.
pub const FERRET_REGULAR_EXTENSION_LARGE: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 10_485_760,
        k: 458_000,
        t: 1280,
    },
    lpn_type: LpnType::Regular,
};

/// Ferret config with uniform LPN parameters.
/// Parameters for setup with small extension output.
pub const FERRET_UNIFORM_SETUP_SMALL: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 98_000,
        k: 4_450,
        t: 1_600,
    },
    lpn_type: LpnType::Uniform,
};

/// Ferret config with uniform LPN parameters.
/// Parameters for extension with small extension output.
pub const FERRET_UNIFORM_EXTENSION_SMALL: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 1_071_888,
        k: 40_800,
        t: 1720,
    },
    lpn_type: LpnType::Uniform,
};

/// Ferret config with uniform LPN parameters.
/// Parameters for setup with medium extension output.
pub const FERRET_UNIFORM_SETUP_MEDIUM: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 283_648,
        k: 18_584,
        t: 1_108,
    },
    lpn_type: LpnType::Uniform,
};

/// Ferret config with uniform LPN parameters.
/// Parameters for extension with medium extension output.
pub const FERRET_UNIFORM_EXTENSION_MEDIUM: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 5_324_800,
        k: 240_000,
        t: 1_300,
    },
    lpn_type: LpnType::Uniform,
};

/// Ferret config with uniform LPN parameters.
/// Parameters for setup with large extension output.
pub const FERRET_UNIFORM_SETUP_LARGE: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 545_656,
        k: 34_643,
        t: 1_050,
    },
    lpn_type: LpnType::Uniform,
};

/// Ferret config with uniform LPN parameters.
/// Parameters for extension with large extension output.
pub const FERRET_UNIFORM_EXTENSION_LARGE: FerretConfig = FerretConfig {
    lpn_parameters: LpnParameters {
        n: 10_488_928,
        k: 458_000,
        t: 1_280,
    },
    lpn_type: LpnType::Uniform,
};

#[cfg(test)]
mod tests {
    use super::*;
    use futures::TryFutureExt as _;
    use mpz_common::executor::test_st_executor;
    use mpz_core::lpn::LpnParameters;
    use mpz_ot_core::{ferret::LpnType, test::assert_cot, RCOTReceiverOutput, RCOTSenderOutput};
    use rstest::*;

    use crate::{ideal::cot::ideal_rcot, Correlation, OTError, RandomCOTReceiver, RandomCOTSender};

    // l = n - k = 8380
    const LPN_PARAMETERS_TEST: LpnParameters = LpnParameters {
        n: 9600,
        k: 1220,
        t: 600,
    };

    #[rstest]
    #[case::uniform(LpnType::Uniform)]
    #[case::regular(LpnType::Regular)]
    #[tokio::test]
    async fn test_ferret(#[case] lpn_type: LpnType) {
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);

        let (rcot_sender, rcot_receiver) = ideal_rcot();

        let config = FerretConfig::new(LPN_PARAMETERS_TEST, lpn_type);

        let mut sender = Sender::new(config.clone(), rcot_sender);
        let mut receiver = Receiver::new(config, rcot_receiver);

        tokio::try_join!(
            sender.setup(&mut ctx_sender).map_err(OTError::from),
            receiver.setup(&mut ctx_receiver).map_err(OTError::from)
        )
        .unwrap();

        // extend once.
        let count = LPN_PARAMETERS_TEST.k;
        tokio::try_join!(
            sender.extend(&mut ctx_sender, count).map_err(OTError::from),
            receiver
                .extend(&mut ctx_receiver, count)
                .map_err(OTError::from)
        )
        .unwrap();

        // extend twice
        let count = 10000;
        tokio::try_join!(
            sender.extend(&mut ctx_sender, count).map_err(OTError::from),
            receiver
                .extend(&mut ctx_receiver, count)
                .map_err(OTError::from)
        )
        .unwrap();

        let (
            RCOTSenderOutput {
                id: sender_id,
                msgs: u,
            },
            RCOTReceiverOutput {
                id: receiver_id,
                choices: b,
                msgs: w,
            },
        ) = tokio::try_join!(
            sender.send_random_correlated(&mut ctx_sender, count),
            receiver.receive_random_correlated(&mut ctx_receiver, count)
        )
        .unwrap();

        assert_eq!(sender_id, receiver_id);
        assert_cot(sender.delta(), &b, &u, &w);
    }
}
