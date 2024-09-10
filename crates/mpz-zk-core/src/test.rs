//! test functions.

use mpz_core::Block;

use crate::{VOPEReceiverOutput, VOPESenderOutput};

/// Check polynomial relation.
pub fn poly_check(a: &[Block], b: Block, delta: Block) -> bool {
    b == a
        .iter()
        .rev()
        .fold(Block::ZERO, |acc, &x| x ^ (delta.gfmul(acc)))
}

/// Assert VOPE relation.
pub fn assert_vope(
    send: VOPESenderOutput<Block>,
    recv: VOPEReceiverOutput<Block>,
    delta: Block,
) -> bool {
    let send = send.eval;
    let recv = recv.coeff;
    poly_check(&recv, send, delta)
}
