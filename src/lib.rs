#![allow(non_snake_case)]

use bit_vec::BitVec;
use ecdsa_fun::fun::marker::{Secret, Zero};
use rand::{CryptoRng, RngCore};

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
        let ed25519 = curve25519_dalek::scalar::Scalar::random(rng);
        let bytes = ed25519.to_bytes();

        Self(bytes)
    }

    /// Bit representation of the scalar.
    pub fn bits(&self) -> BitVec {
        BitVec::from_bytes(&self.0).iter().rev().collect()
    }

    pub fn into_secp256k1(self) -> ecdsa_fun::fun::Scalar<Secret, Zero> {
        self.into()
    }

    pub fn into_ed25519(self) -> curve25519_dalek::scalar::Scalar {
        self.into()
    }
}

impl From<Scalar> for ecdsa_fun::fun::Scalar<Secret, Zero> {
    fn from(from: Scalar) -> Self {
        Self::from_bytes_mod_order(from.0)
    }
}

impl From<Scalar> for curve25519_dalek::scalar::Scalar {
    fn from(from: Scalar) -> Self {
        Self::from_bytes_mod_order(from.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigint::U256;
    use ecdsa_fun::fun::{
        g,
        marker::{Jacobian, Mark, Normal},
        s,
    };
    use rand::thread_rng;

    #[test]
    fn secp256k1_key_from_ed25519_key_produces_same_bytes() {
        let ed25519 = curve25519_dalek::scalar::Scalar::random(&mut thread_rng());
        let ed25519_bytes = ed25519.to_bytes();

        let secp256k1 = ecdsa_fun::fun::Scalar::from_bytes_mod_order(ed25519_bytes);
        let secp256k1_bytes = secp256k1.to_bytes();

        assert_eq!(ed25519_bytes, secp256k1_bytes);
    }

    #[test]
    fn decompose_scalar_into_bits_roundtrip() {
        let x = Scalar::random(&mut thread_rng());
        let G = ecdsa_fun::fun::G;

        let mut X = ecdsa_fun::fun::Point::zero();
        let two = U256::from(2u8);

        for (i, b_i) in x.bits().iter().enumerate() {
            if !b_i {
                continue;
            }

            let exp = two.pow(U256::from(i));
            let exp = ecdsa_fun::fun::Scalar::<Secret, Zero>::from_bytes(exp.into()).unwrap();

            X = g!(X + exp * G).mark::<Normal>();
        }

        let x = ecdsa_fun::fun::Scalar::from(x);
        assert_eq!(g!(x * G).mark::<Normal>(), X)
    }

    #[test]
    fn point_equals_commitments_minus_public_blinding_factor() {
        let x = Scalar::random(&mut thread_rng());

        let G = ecdsa_fun::fun::G;
        let G_prime = ecdsa_fun::fun::Point::random(&mut thread_rng());

        let mut rs = Vec::new();
        let mut Cs = Vec::new();
        for b_i in x.bits().iter() {
            let b_i = if b_i {
                ecdsa_fun::fun::Scalar::one().mark::<Zero>()
            } else {
                ecdsa_fun::fun::Scalar::zero()
            };

            let r_i = ecdsa_fun::fun::Scalar::random(&mut thread_rng());

            let C_i = g!(b_i * G + r_i * G_prime);

            rs.push(r_i);
            Cs.push(C_i);
        }

        let mut C = ecdsa_fun::fun::Point::zero().mark::<Jacobian>();
        let two = U256::from(2u8);
        for (i, C_i) in Cs.iter().enumerate() {
            let exp = two.pow(U256::from(i));
            let exp = ecdsa_fun::fun::Scalar::<Secret, Zero>::from_bytes(exp.into()).unwrap();

            C = g!(C + exp * C_i);
        }

        let mut r = ecdsa_fun::fun::Scalar::zero();
        for (i, r_i) in rs.iter().enumerate() {
            let exp = two.pow(U256::from(i));
            let exp = ecdsa_fun::fun::Scalar::<Secret, Zero>::from_bytes(exp.into()).unwrap();

            r = s!(r + exp * r_i)
        }

        let x = ecdsa_fun::fun::Scalar::from(x);
        assert_eq!(g!(C - r * G_prime), g!(x * G));
    }
}
