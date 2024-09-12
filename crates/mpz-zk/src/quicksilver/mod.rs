//! Implementation of QuickSilver (https://eprint.iacr.org/2021/076.pdf).

mod error;
mod prover;
mod verifier;

pub use error::{ProverError, VerifierError};
pub use prover::Prover;
pub use verifier::Verifier;

#[cfg(test)]
mod tests {
    use crate::{
        quicksilver::{Prover, Verifier},
        ZKError,
    };
    use aes::{
        cipher::{BlockEncrypt, KeyInit},
        Aes128,
    };
    use futures::TryFutureExt;
    use mpz_circuits::{circuits::AES128, evaluate};
    use mpz_common::executor::test_st_executor;
    use mpz_core::prg::Prg;
    use mpz_ot::ideal::cot::ideal_rcot_with_delta;

    #[tokio::test]
    async fn test_qs() {
        let (mut ctx_sender, mut ctx_receiver) = test_st_executor(8);

        let mut delta = Prg::new().random_block();
        delta.set_lsb();

        let (mut rcot_sender, mut rcot_receiver) = ideal_rcot_with_delta(delta);

        let mut prover = Prover::new();
        let mut verifier = Verifier::new(delta);

        let key = [69u8; 16];
        let msg = [42u8; 16];

        let output = evaluate!(AES128, fn(key, msg) -> [u8; 16]).unwrap();

        let expected: [u8; 16] = {
            let cipher = Aes128::new_from_slice(&key).unwrap();
            let mut out = msg.into();
            cipher.encrypt_block(&mut out);
            out.into()
        };

        assert_eq!(output, expected);

        let input_value = [key, msg].concat();
        tokio::try_join!(
            prover
                .prove(&mut ctx_sender, &AES128, input_value, &mut rcot_receiver)
                .map_err(ZKError::from),
            verifier
                .verify(&mut ctx_receiver, &AES128, output, &mut rcot_sender)
                .map_err(ZKError::from)
        )
        .unwrap();

        assert!(verifier.checked())
    }
}
