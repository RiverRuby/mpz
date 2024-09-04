//! This is the implementation of vector oblivious polynomial evaluation (VOPE) based on Figure 4 in https://eprint.iacr.org/2021/076.pdf

pub mod error;
pub mod receiver;
pub mod sender;

#[cfg(test)]
mod tests {
    use crate::{
        vope::{receiver::Receiver, sender::Sender},
        VOPEError,
    };
    use futures::TryFutureExt;
    use mpz_common::executor::test_st_executor;
    use mpz_core::Block;
    use mpz_ot::{
        ideal::cot::{ideal_rcot, IdealCOTReceiver, IdealCOTSender},
        Correlation,
    };
    use mpz_zk_core::test::poly_check;

    fn setup() -> (Sender<IdealCOTSender>, Receiver<IdealCOTReceiver>, Block) {
        let (rcot_sender, rcot_receiver) = ideal_rcot();

        let delta = rcot_sender.delta();

        let sender = Sender::new(rcot_sender);
        let receiver = Receiver::new(rcot_receiver);

        (sender, receiver, delta)
    }

    #[tokio::test]
    async fn test_vope() {
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);

        let (mut sender, mut receiver, delta) = setup();

        sender.setup_with_delta(delta).unwrap();
        receiver.setup().unwrap();

        let d = 1;

        let (output_sender, output_receiver) = tokio::try_join!(
            sender.extend(&mut ctx_sender, d).map_err(VOPEError::from),
            receiver
                .extend(&mut ctx_receiver, d)
                .map_err(VOPEError::from)
        )
        .unwrap();

        assert!(poly_check(&output_receiver, output_sender, delta));

        let d = 5;

        let (output_sender, output_receiver) = tokio::try_join!(
            sender.extend(&mut ctx_sender, d).map_err(VOPEError::from),
            receiver
                .extend(&mut ctx_receiver, d)
                .map_err(VOPEError::from)
        )
        .unwrap();

        assert!(poly_check(&output_receiver, output_sender, delta));
    }
}
