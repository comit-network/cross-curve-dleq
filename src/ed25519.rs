use crate::Commit;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use sha2::{Digest, Sha512};

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

const TWO: Scalar = Scalar::from_bits([
    2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

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
    s_is.iter().enumerate().fold(Scalar::zero(), |acc, (i, s)| {
        let exp = two_to_the_power_of(i);

        acc + exp * s
    })
}

/// Check that the sum of `C_H_i * 2^i` minus `s * H_PRIME` is equal to the
/// public value `xH` for all `C_H_i` in `C_H_is`.
pub(crate) fn verify_bit_commitments_represent_dleq_commitment(
    C_H_is: &[Point],
    X: Point,
    s: Scalar,
) -> bool {
    let C_H =
        C_H_is
            .iter()
            .enumerate()
            .fold(Scalar::zero() * Point::default(), |acc, (i, C_H_i)| {
                let exp = two_to_the_power_of(i);

                acc + exp * C_H_i
            });

    C_H - s * *H_PRIME == X
}

fn two_to_the_power_of(exp: usize) -> Scalar {
    (0..exp).fold(Scalar::one(), |acc, _| acc * TWO)
}

#[cfg_attr(
    feature = "serde",
    serde(crate = "serde_crate"),
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[derive(Clone, Debug)]
pub struct Signature {
    R: Point,
    s: Scalar,
}

impl Signature {
    pub fn new<R: rand::RngCore + rand::CryptoRng>(rng: &mut R, x: &Scalar, digest: &[u8]) -> Self {
        let r = Scalar::random(rng);
        let R = &r * &H;

        let X = x * &H;

        let hash = Sha512::default()
            .chain(&R.compress().as_bytes())
            .chain(&X.compress().as_bytes())
            .chain(digest)
            .finalize();

        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&hash);

        let c = Scalar::from_bytes_mod_order_wide(&bytes);

        let s = r + c * x;

        Self { R, s }
    }

    #[must_use]
    pub fn verify(&self, X: &Point, digest: &[u8]) -> bool {
        let hash = Sha512::default()
            .chain(&self.R.compress().as_bytes())
            .chain(&X.compress().as_bytes())
            .chain(digest)
            .finalize();

        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&hash);

        let c = Scalar::from_bytes_mod_order_wide(&bytes);

        let R_prime = &self.s * &H - c * X;

        R_prime == self.R
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to verify signature")]
pub struct VerificationError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proptest;
    use ::proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn ed_bit_commitments_represent_dleq_commitment(x in proptest::scalar()) {
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
