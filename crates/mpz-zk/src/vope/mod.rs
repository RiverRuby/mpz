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
    use mpz_ot::{ideal::cot::ideal_rcot, Correlation};
    use mpz_zk_core::test::assert_vope;

    #[tokio::test]
    async fn test_vope() {
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);

        let (mut rcot_sender, mut rcot_receiver) = ideal_rcot();

        let mut sender = Sender::new();
        let mut receiver = Receiver::new();

        let delta = rcot_sender.delta();

        sender.setup(delta).unwrap();
        receiver.setup().unwrap();

        let d = 1;

        let (output_sender, output_receiver) = tokio::try_join!(
            sender
                .send(&mut ctx_sender, &mut rcot_sender, d)
                .map_err(VOPEError::from),
            receiver
                .receive(&mut ctx_receiver, &mut rcot_receiver, d)
                .map_err(VOPEError::from)
        )
        .unwrap();

        assert!(assert_vope(output_sender, output_receiver, delta));

        let d = 5;

        let (output_sender, output_receiver) = tokio::try_join!(
            sender
                .send(&mut ctx_sender, &mut rcot_sender, d)
                .map_err(VOPEError::from),
            receiver
                .receive(&mut ctx_receiver, &mut rcot_receiver, d)
                .map_err(VOPEError::from)
        )
        .unwrap();

        assert!(assert_vope(output_sender, output_receiver, delta));
    }
}
