use crate::Commit;
use bigint::U256;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

pub use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE as H, scalar::Scalar};

pub type Point = EdwardsPoint;

lazy_static::lazy_static! {
    /// Alternate generator of ed25519.
    ///
    /// Obtained by hashing `curve25519_dalek::constants::ED25519_BASEPOINT_POINT`.
    /// Originally used in Monero Ring Confidential Transactions.
    pub static ref H_PRIME: EdwardsPoint = {
        CompressedEdwardsY(hex_literal::hex!(
            "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
        ))
        .decompress()
        .expect("edwards point")
    };
}

pub(crate) struct PedersenCommitment(Point);

impl PedersenCommitment {
    /// Generate a Pedersen Commitment for the scalar `x`.
    pub(crate) fn new<R: rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
        x: Scalar,
    ) -> (Self, Scalar) {
        let s = Scalar::random(rng);
        let C_H = &x * &H + s * *H_PRIME;

        (Self(C_H), s)
    }
}

impl Commit for PedersenCommitment {
    type Commitment = Point;
    type Blinder = Scalar;

    fn commit<R: rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
        bit: bool,
    ) -> (Self::Commitment, Self::Blinder) {
        let b = bit_as_scalar(bit);
        let (PedersenCommitment(C_H), s) = PedersenCommitment::new(rng, b);

        (C_H, s)
    }
}

/// Transform a bit into a `ed25519::Scalar`.
pub(crate) fn bit_as_scalar(bit: bool) -> Scalar {
    if bit {
        Scalar::one()
    } else {
        Scalar::zero()
    }
}

// TODO: Should not need to use `bigint::U256` by doing something like
// what we do in `secp256k1.rs`.

/// Calculate sum of `s_i * 2^i`, where `i` is the bit index.
pub(crate) fn blinder_sum(s_is: &[Scalar]) -> Scalar {
    let two = U256::from(2u8);
    s_is.iter().enumerate().fold(Scalar::zero(), |acc, (i, s)| {
        let exp = two.pow(U256::from(i));
        let exp = Scalar::from_bytes_mod_order(exp.into());

        acc + exp * s
    })
}

/// Check that the sum of `C_H_i * 2^i` minus `s * H_PRIME` is equal to the
/// public value `xH` for all `C_H_i` in `C_H_is`.
pub(crate) fn verify_bit_commitments_represent_dleq_commitment(
    C_H_is: &[Point],
    xH: Point,
    s: Scalar,
) -> bool {
    let two = U256::from(2u8);

    let C_H =
        C_H_is
            .iter()
            .enumerate()
            .fold(Scalar::zero() * Point::default(), |acc, (i, C_H_i)| {
                let exp = two.pow(U256::from(i));
                let exp = Scalar::from_bytes_mod_order(exp.into());

                acc + exp * C_H_i
            });

    C_H - s * *H_PRIME == xH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest;
    use ::proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn bit_commitments_represent_dleq_commitment(x in proptest::scalar()) {
            let mut rng = rand::thread_rng();

            let xH = &x.into_ed25519() * &H;

            let (C_H_is, s_is) = x
                .bits()
                .iter()
                .map(|b| PedersenCommitment::commit(&mut rng, b))
                .unzip::<_, _, Vec<_>, Vec<_>>();

            let s = blinder_sum(&s_is);

            assert!(verify_bit_commitments_represent_dleq_commitment(
                &C_H_is, xH, s
            ));
        }
    }
}
