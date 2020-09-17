use crate::Commit;

use bigint::U256;
pub use ecdsa_fun::fun::{g, marker, s, Point, Scalar, G};

use marker::{Jacobian, Mark, NonZero, Secret, Zero};

lazy_static::lazy_static! {
    /// Alternate generator of secp256k1.
    pub static ref G_PRIME: Point =
        Point::from_bytes(hex_literal::hex!(
            "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        ))
        .expect("valid point");
}

pub struct PedersenCommitment(Point<Jacobian>);

impl PedersenCommitment {
    /// Generate a Pedersen Commitment for the scalar `x`.
    pub fn new<R: rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
        x: &Scalar<Secret, Zero>,
    ) -> (Self, Scalar) {
        let r = Scalar::random(rng);
        let commitment = g!(x * G + r * G_PRIME)
            .mark::<NonZero>()
            .expect("r to be non-zero");

        (Self(commitment), r)
    }
}

impl Commit for PedersenCommitment {
    type Commitment = Point<Jacobian>;
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
pub fn bit_as_scalar(bit: bool) -> Scalar<Secret, Zero> {
    if bit {
        Scalar::one().mark::<Zero>()
    } else {
        Scalar::zero()
    }
}

/// Calculate sum of `r_i * 2^i`, where `i` is the bit index.
pub fn blinder_sum(r_is: &[Scalar]) -> Scalar {
    let two = U256::from(2u8);
    r_is.iter()
        .enumerate()
        .fold(Scalar::zero(), |acc, (i, r)| {
            let exp = two.pow(U256::from(i));
            let exp = Scalar::from_bytes(exp.into()).unwrap();

            s!(acc + exp * r)
        })
        .mark::<NonZero>()
        .expect("non-zero sum of blinders")
}

/// Check that the sum of `C_G_i * 2^i` minus `r * G_PRIME` is equal to the
/// public value `xG` for all `C_G_i` in `C_G_is`.
pub fn verify_bit_commitments_represent_dleq_commitment(
    C_G_is: &[Point<Jacobian>],
    xG: &Point<Jacobian>,
    r: &Scalar,
) -> bool {
    let two = U256::from(2u8);

    let C_G =
        C_G_is
            .iter()
            .enumerate()
            .fold(Point::zero().mark::<Jacobian>(), |acc, (i, C_G_i)| {
                let exp = two.pow(U256::from(i));
                let exp = Scalar::from_bytes_mod_order(exp.into());

                g!(acc + exp * C_G_i)
            });

    &g!(C_G - r * G_PRIME) == xG
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

            let xG = g!({ x.into_secp256k1() } * G);

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
