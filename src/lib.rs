#![allow(non_snake_case)]

use bit_vec::BitVec;
use ed25519::{H, H_PRIME};
use rand::{CryptoRng, RngCore};
use secp256k1::{
    g,
    marker::{Jacobian, Mark, Public, Secret, Zero},
    G, G_PRIME,
};

mod secp256k1 {
    use ecdsa_fun::fun::marker::Mark;

    pub use ecdsa_fun::fun::{g, marker, s, Point, Scalar, G};

    lazy_static::lazy_static! {
        /// Alternate generator of secp256k1.
        pub static ref G_PRIME: Point<marker::Jacobian> =
            Point::from_bytes(hex_literal::hex!(
                "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            ))
            .expect("valid point")
            .mark::<marker::Jacobian>();
    }
}

mod ed25519 {
    use curve25519_dalek::{
        self,
        edwards::{CompressedEdwardsY, EdwardsPoint},
    };

    pub use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as H, scalar::Scalar};

    pub type Point = EdwardsPoint;

    lazy_static::lazy_static! {
        /// Alternate generator of ed25519.
        pub static ref H_PRIME: EdwardsPoint = {
            CompressedEdwardsY(hex_literal::hex!(
                "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
            ))
            .decompress()
            .expect("edwards point")
        };
    }
}

/// A scalar that is valid for both secp256k1 and ed25519.
pub struct Scalar([u8; 32]);

impl Scalar {
    /// Generate a random scalar.
    ///
    /// Given the smaller curve order for ed25519, any scalar for
    /// ed25519 will have the same byte representation for secp256k1.
    /// We can therefore use the `curve25519_dalek::scalar::Scalar`
    /// type to generate our type.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let ed25519 = ed25519::Scalar::random(rng);
        let bytes = ed25519.to_bytes();

        Self(bytes)
    }

    /// Bit representation of the scalar.
    pub fn bits(&self) -> BitVec {
        BitVec::from_bytes(&self.0).iter().rev().collect()
    }

    // TODO: This is always 256 bits, so we could produce an array of that
    // size instead of a vector.

    /// Generate openings for Pedersen Commitments to each bit on both secp256k1 and ed25519.
    pub fn bit_openings<R: RngCore + CryptoRng>(&self, rng: &mut R) -> BitOpenings {
        self.bits()
            .iter()
            .map(|bit| {
                (
                    BitOpening::<secp256k1::Scalar>::new(rng, bit),
                    BitOpening::<ed25519::Scalar>::new(rng, bit),
                )
            })
            .collect()
    }

    pub fn into_secp256k1(self) -> secp256k1::Scalar<Secret, Zero> {
        self.into()
    }

    pub fn into_ed25519(self) -> ed25519::Scalar {
        self.into()
    }
}

pub type BitOpenings = Vec<(BitOpening<secp256k1::Scalar>, BitOpening<ed25519::Scalar>)>;

/// The opening to a Pedersen Commitment to the value of a bit.
pub struct BitOpening<S> {
    bit: bool,
    blinder: S,
}

pub struct BitCommitment<P>(P);

impl BitOpening<secp256k1::Scalar> {
    fn new<R: RngCore + CryptoRng>(rng: &mut R, bit: bool) -> Self {
        let blinder = secp256k1::Scalar::random(rng);

        Self { bit, blinder }
    }

    fn commit(&self) -> BitCommitment<secp256k1::Point<Jacobian, Public, Zero>> {
        let b = if self.bit {
            secp256k1::Scalar::one().mark::<Zero>()
        } else {
            secp256k1::Scalar::zero()
        };

        let r = self.blinder.clone();

        BitCommitment(g!(b * G + r * G_PRIME))
    }
}

impl BitOpening<ed25519::Scalar> {
    fn new<R: RngCore + CryptoRng>(rng: &mut R, bit: bool) -> Self {
        let blinder = ed25519::Scalar::random(rng);

        Self { bit, blinder }
    }

    fn commit(&self) -> BitCommitment<ed25519::Point> {
        let b = if self.bit {
            ed25519::Scalar::one()
        } else {
            ed25519::Scalar::zero()
        };

        let s = self.blinder;

        BitCommitment(b * H + s * *H_PRIME)
    }
}

impl From<Scalar> for secp256k1::Scalar<Secret, Zero> {
    fn from(from: Scalar) -> Self {
        Self::from_bytes_mod_order(from.0)
    }
}

impl From<Scalar> for ed25519::Scalar {
    fn from(from: Scalar) -> Self {
        Self::from_bytes_mod_order(from.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigint::U256;
    use ecdsa_fun::fun::{marker::Normal, s};
    use rand::thread_rng;

    #[test]
    fn secp256k1_key_from_ed25519_key_produces_same_bytes() {
        let ed25519 = ed25519::Scalar::random(&mut thread_rng());
        let ed25519_bytes = ed25519.to_bytes();

        let secp256k1 = secp256k1::Scalar::from_bytes_mod_order(ed25519_bytes);
        let secp256k1_bytes = secp256k1.to_bytes();

        assert_eq!(ed25519_bytes, secp256k1_bytes);
    }

    #[test]
    fn decompose_scalar_into_bits_roundtrip() {
        let x = Scalar::random(&mut thread_rng());

        let mut X = secp256k1::Point::zero();
        let two = U256::from(2u8);

        for (i, b_i) in x.bits().iter().enumerate() {
            if !b_i {
                continue;
            }

            let exp = two.pow(U256::from(i));
            let exp = secp256k1::Scalar::<Secret, Zero>::from_bytes(exp.into()).unwrap();

            X = g!(X + exp * G).mark::<Normal>();
        }

        let x = secp256k1::Scalar::from(x);
        assert_eq!(g!(x * G).mark::<Normal>(), X)
    }

    #[test]
    fn point_equals_commitments_minus_public_blinding_factor() {
        let x = Scalar::random(&mut thread_rng());

        let mut rs = Vec::new();
        let mut Cs = Vec::new();
        for b_i in x.bits().iter() {
            let b_i = if b_i {
                secp256k1::Scalar::one().mark::<Zero>()
            } else {
                secp256k1::Scalar::zero()
            };

            let r_i = secp256k1::Scalar::random(&mut thread_rng());

            let C_i = g!(b_i * G + r_i * G_PRIME);

            rs.push(r_i);
            Cs.push(C_i);
        }

        let mut C = secp256k1::Point::zero().mark::<Jacobian>();
        let two = U256::from(2u8);
        for (i, C_i) in Cs.iter().enumerate() {
            let exp = two.pow(U256::from(i));
            let exp = secp256k1::Scalar::<Secret, Zero>::from_bytes(exp.into()).unwrap();

            C = g!(C + exp * C_i);
        }

        let mut r = secp256k1::Scalar::zero();
        for (i, r_i) in rs.iter().enumerate() {
            let exp = two.pow(U256::from(i));
            let exp = secp256k1::Scalar::<Secret, Zero>::from_bytes(exp.into()).unwrap();

            r = s!(r + exp * r_i)
        }

        let x = secp256k1::Scalar::from(x);
        assert_eq!(g!(C - r * G_PRIME), g!(x * G));
    }
}
