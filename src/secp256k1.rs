use crate::Commit;
use ecdsa_fun::fun::marker::{Jacobian, Mark, NonZero, Normal, Secret, Zero};
use std::num::NonZeroU32;

pub use ecdsa_fun::fun::{g, marker, marker::PointType, s, Point, Scalar, G};

lazy_static::lazy_static! {
    /// Alternate generator of secp256k1.
    ///
    /// Obtained by hashing `ecdsa_fun::fun::G`. Originally used in Grin.
    pub static ref G_PRIME: Point =
        Point::from_bytes(hex_literal::hex!(
            "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        ))
        .expect("valid point");

    static ref TWO: Scalar =
        Scalar::from_non_zero_u32(NonZeroU32::new(2).expect("2 != 0"));
}

pub(crate) struct PedersenCommitment(Point);

impl PedersenCommitment {
    /// Generate a Pedersen Commitment for the scalar `x`.
    pub(crate) fn new<R: rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
        x: &Scalar<Secret, Zero>,
    ) -> (Self, Scalar) {
        let r = Scalar::random(rng);
        let commitment = g!(x * G + r * G_PRIME)
            .mark::<Normal>()
            .mark::<NonZero>()
            .expect("r to be non-zero");

        (Self(commitment), r)
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
        let (PedersenCommitment(C_G), r) = PedersenCommitment::new(rng, &b);

        (C_G, r)
    }
}

/// Transform a bit into a `secp256k1::Scalar`.
pub(crate) fn bit_as_scalar(bit: bool) -> Scalar<Secret, Zero> {
    if bit {
        Scalar::one().mark::<Zero>()
    } else {
        Scalar::zero()
    }
}

/// Calculate sum of `r_i * 2^i`, where `i` is the bit index.
pub(crate) fn blinder_sum(r_is: &[Scalar]) -> Scalar {
    r_is.iter()
        .enumerate()
        .fold(Scalar::zero(), |acc, (i, r)| {
            let exp = two_to_the_power_of(i);
            s!(acc + exp * r)
        })
        .mark::<NonZero>()
        .expect("non-zero sum of blinders")
}

/// Check that the sum of `C_G_i * 2^i` minus `r * G_PRIME` is equal to the
/// public value `xG` for all `C_G_i` in `C_G_is`.
pub(crate) fn verify_bit_commitments_represent_dleq_commitment(
    C_G_is: &[Point],
    xG: &Point,
    r: &Scalar,
) -> bool {
    let C_G =
        C_G_is
            .iter()
            .enumerate()
            .fold(Point::zero().mark::<Jacobian>(), |acc, (i, C_G_i)| {
                let exp = two_to_the_power_of(i);
                g!(acc + exp * C_G_i)
            });

    &g!(C_G - r * G_PRIME) == xG
}

fn two_to_the_power_of(exp: usize) -> Scalar {
    (0..exp).fold(Scalar::one(), |acc, _| s!(acc * TWO))
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

            let xG = g!({ x.into_secp256k1() } * G).mark::<Normal>();

            let (C_G_is, r_is) = x
                .bits()
                .iter()
                .map(|b| PedersenCommitment::commit(&mut rng, b))
                .unzip::<_, _, Vec<_>, Vec<_>>();

            let r = blinder_sum(&r_is);

            assert!(verify_bit_commitments_represent_dleq_commitment(
                &C_G_is, &xG, &r
            ));
        }
    }
}
