#![allow(non_snake_case)]

mod ed25519;
mod secp256k1;

use crate::{
    ed25519::{H, H_PRIME},
    secp256k1::{
        g,
        marker::{Mark, Secret, Zero},
        G, G_PRIME,
    },
};
use bit_vec::BitVec;
use ecdsa_fun::fun::marker::Jacobian;
use ecdsa_fun::fun::{
    marker::{NonZero, Normal},
    s,
};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::ops::{Add, Sub};

/// A scalar that is valid for both secp256k1 and ed25519.
///
/// Any valid scalar for ed25519 has the same bit representation for
/// secp256k1, due to the smaller curve order for ed25519 compared to
/// secp256k1.
///
/// On the other hand, not all valid scalars for secp256k1 have the
/// same bit representation for ed25519.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Scalar([u8; 32]);

impl Scalar {
    /// Generate a random scalar.
    ///
    /// To ensure that the scalar is valid and equal for both
    /// secp256k1 and ed25519, we delegate to an `ed25519::Scalar`
    /// API.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let ed25519 = ed25519::Scalar::random(rng);
        let bytes = ed25519.to_bytes();

        Self(bytes)
    }

    /// Decompose scalar into bits.
    ///
    /// The vector of bits is ordered from least significant bit to
    /// most significant bit.
    pub fn bits(&self) -> BitVec {
        // We reverse the vector of bits to ensure that the bits are
        // ordered from LSB to MSB.
        BitVec::from_bytes(&self.0).iter().rev().collect()
    }

    pub fn into_secp256k1(self) -> secp256k1::Scalar {
        self.into()
    }

    pub fn into_ed25519(self) -> ed25519::Scalar {
        self.into()
    }
}

/// Implement addition for `Scalar`.
///
/// We choose to rely on `secp256k1::Scalar` for this, but it should
/// be equivalent to use `ed25519::Scalar` instead.
impl Add<Scalar> for Scalar {
    type Output = Scalar;
    fn add(self, rhs: Scalar) -> Self::Output {
        let res = s!({ self.into_secp256k1() } + { rhs.into_secp256k1() });

        Scalar(res.to_bytes())
    }
}

/// Implement subtraction for `Scalar`.
///
/// We choose to rely on `secp256k1::Scalar` for this, but it should
/// be equivalent to use `ed25519::Scalar` instead.
impl Sub<Scalar> for Scalar {
    type Output = Scalar;
    fn sub(self, rhs: Scalar) -> Self::Output {
        let res = s!({ self.into_secp256k1() } - { rhs.into_secp256k1() });

        Scalar(res.to_bytes())
    }
}

// TODO: Consider introducing `Commitment` and `Blinder` types.

/// Generate Pedersen Commitment to the value of a bit. Also return the blinder used.
pub trait Commit {
    type Commitment;
    type Blinder;
    fn commit<R: RngCore + CryptoRng>(rng: &mut R, bit: bool) -> (Self::Commitment, Self::Blinder);
}

#[derive(Debug, Clone, Copy)]
pub struct BitCommitment<P>(P);

impl From<[u8; 32]> for Scalar {
    fn from(from: [u8; 32]) -> Self {
        let scalar = ed25519::Scalar::from_bytes_mod_order(from);
        Self(*scalar.as_bytes())
    }
}

impl From<Scalar> for secp256k1::Scalar {
    fn from(from: Scalar) -> Self {
        secp256k1::Scalar::<Secret, Zero>::from_bytes_mod_order(from.0)
            .mark::<NonZero>()
            .expect("non-zero scalar")
    }
}

impl From<Scalar> for ed25519::Scalar {
    fn from(from: Scalar) -> Self {
        Self::from_bytes_mod_order(from.0)
    }
}

pub struct Proof {
    /// Pedersen Commitments for bits of the secp256k1 scalar.
    ///
    /// Mathematical expression: `b_i * G_PRIME + r_i * G`, where
    /// `b_i` is the `ith` bit, `r_i` is its blinder, and `G` and
    /// `G_PRIME` are generators of secp256k1.
    C_G_is: Vec<secp256k1::Point<Jacobian>>,
    /// Pedersen Commitments for bits of the ed25519 scalar.
    ///
    /// Mathematical expression: `b_i * H_PRIME + s_i * H`, where
    /// `b_i` is the `ith` bit, `s_i` is its blinder, and `H` and
    /// `H_PRIME` are generators of secp256k1.
    C_H_is: Vec<ed25519::Point>,
    /// Challenges for proofs that a bit is equal to 0.
    c_0s: Vec<Scalar>,
    /// Challenges for proofs that a bit is equal to 1.
    c_1s: Vec<Scalar>,
    /// Announcements for proofs that a bit of the secp256k1 scalar is
    /// equal to 0.
    U_G_0s: Vec<secp256k1::Point>,
    /// Announcements for proofs that a bit of the ed25519 scalar is
    /// equal to 0.
    U_H_0s: Vec<ed25519::Point>,
    /// Announcements for proofs that a bit of the secp256k1 scalar is
    /// equal to 1.
    U_G_1s: Vec<secp256k1::Point>,
    /// Announcements for proofs that a bit of the ed25519 scalar is
    /// equal to 0.
    U_H_1s: Vec<ed25519::Point>,
    /// Responses for proofs that a bit of the secp256k1 scalar is
    /// equal to 0.
    res_G_0s: Vec<secp256k1::Scalar>,
    /// Responses for proofs that a bit of the ed25519 scalar is equal
    /// to 0.
    res_H_0s: Vec<ed25519::Scalar>,
    /// Responses for proofs that a bit of the secp256k1 scalar is
    /// equal to 1.
    res_G_1s: Vec<secp256k1::Scalar>,
    /// Responses for proofs that a bit of the ed25519 scalar is equal
    /// to 1.
    res_H_1s: Vec<ed25519::Scalar>,
    /// Blinder for the overall Pedersen Commitment of the secp256k1
    /// scalar.
    ///
    /// Calculation: sum of `r_i * 2^i`, where `i` is the index of the
    /// bit and `r_i` its blinder.
    r: secp256k1::Scalar,
    /// Blinder for the overall Pedersen Commitment of the ed25519
    /// scalar.
    ///
    /// Calculation: sum of `s_i * 2^i`, where `i` is the index of the
    /// bit and `s_i` its blinder.
    s: ed25519::Scalar,
}

impl Proof {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, witness: &Scalar) -> Proof {
        let bits = witness.bits();

        let mut C_G_is = Vec::new();
        let mut r_is = Vec::new();

        let mut C_H_is = Vec::new();
        let mut s_is = Vec::new();

        let mut c_cheats = Vec::new();

        let mut U_G_0s = Vec::new();
        let mut U_H_0s = Vec::new();
        let mut U_G_1s = Vec::new();
        let mut U_H_1s = Vec::new();

        let mut res_G_0s = Vec::new();
        let mut res_H_0s = Vec::new();
        let mut res_G_1s = Vec::new();
        let mut res_H_1s = Vec::new();

        for b in bits.iter() {
            // Compute commitment corresponding to each opening
            let (C_G, r) = secp256k1::PedersenCommitment::commit(rng, b);
            let (C_H, s) = ed25519::PedersenCommitment::commit(rng, b);

            // We prove knowledge of the discrete log of C_{G,H} - b{G,H}
            // with respect to {G,H}, proving that it was in fact a
            // commitment to b and proving knowledge of the blinder {r,s}
            let rG_prime = {
                let b = secp256k1::bit_as_scalar(!b);
                g!(C_G - b * G_PRIME)
            };
            let sH_prime = {
                let b = ed25519::bit_as_scalar(!b);
                C_H - b * *H_PRIME
            };

            // Generate randomness for actual bit w.r.t. secp256k1 and ed25519 groups
            let u_G = secp256k1::Scalar::random(rng);
            let u_H = ed25519::Scalar::random(rng);
            // Compute announcement for actual bit w.r.t. secp256k1 and ed25519 groups
            // TODO: Determine if it's supposed to be times G or G_prime, etc.
            let U_G = g!(u_G * G).mark::<Normal>();
            let U_H = u_H * H;

            // Randomly generate challenge for the wrong bit
            let c_cheat = Scalar::random(rng);

            // Randomly generate responses for wrong bit w.r.t. secp256k1 and ed25519 groups
            let res_G_cheat = secp256k1::Scalar::random(rng);
            let res_H_cheat = ed25519::Scalar::random(rng);
            // Build announcements using pre-generated challenge and response w.r.t secp256k1 and ed25519 groups
            let U_G_cheat = {
                let c_cheat = c_cheat.into_secp256k1();
                g!(res_G_cheat * G - c_cheat * rG_prime)
                    .mark::<Normal>()
                    .mark::<NonZero>()
                    .expect("non-zero announcement")
            };
            let U_H_cheat = {
                let c_cheat = c_cheat.into_ed25519();
                res_H_cheat * H - c_cheat * sH_prime
            };

            C_G_is.push(C_G);
            r_is.push(r);

            C_H_is.push(C_H);
            s_is.push(s);

            c_cheats.push(c_cheat);

            if b {
                U_G_0s.push(U_G_cheat);
                U_H_0s.push(U_H_cheat);
                res_G_0s.push(res_G_cheat);
                res_H_0s.push(res_H_cheat);

                U_G_1s.push(U_G);
                U_H_1s.push(U_H);
                res_G_1s.push(u_G);
                res_H_1s.push(u_H);
            } else {
                U_G_0s.push(U_G);
                U_H_0s.push(U_H);
                res_G_0s.push(u_G);
                res_H_0s.push(u_H);

                U_G_1s.push(U_G_cheat);
                U_H_1s.push(U_H_cheat);
                res_G_1s.push(res_G_cheat);
                res_H_1s.push(res_H_cheat);
            }
        }

        let c = Self::compute_challenge(
            &C_G_is
                .clone()
                .into_iter()
                .map(Mark::mark::<Normal>)
                .collect::<Vec<_>>(),
            &C_H_is,
            &U_G_0s,
            &U_G_1s,
            &U_H_0s,
            &U_H_1s,
        );

        let mut c_0s = Vec::new();
        let mut c_1s = Vec::new();

        for (i, b) in bits.iter().enumerate() {
            if b {
                let c_0 = c_cheats[i];
                let c_1 = c - c_0;

                res_G_1s[i] = s!({ &res_G_1s[i] } + { c_1.into_secp256k1() } * { &r_is[i] })
                    .mark::<NonZero>()
                    .expect("non-zero response");
                res_H_1s[i] += c_1.into_ed25519() * s_is[i];

                c_0s.push(c_0);
                c_1s.push(c_1);
            } else {
                let c_1 = c_cheats[i];
                let c_0 = c - c_1;

                res_G_0s[i] = s!({ &res_G_0s[i] } + { c_0.into_secp256k1() } * { &r_is[i] })
                    .mark::<NonZero>()
                    .expect("non-zero response");
                res_H_0s[i] += c_0.into_ed25519() * s_is[i];

                c_0s.push(c_0);
                c_1s.push(c_1);
            };
        }

        let r = secp256k1::blinder_sum(&r_is);
        let s = ed25519::blinder_sum(s_is);

        Proof {
            C_G_is,
            C_H_is,
            c_0s,
            c_1s,
            U_G_0s,
            U_H_0s,
            U_G_1s,
            U_H_1s,
            res_G_0s,
            res_H_0s,
            res_G_1s,
            res_H_1s,
            r,
            s,
        }
    }

    pub fn compute_challenge(
        C_G_is: &[secp256k1::Point],
        C_H_is: &[ed25519::Point],
        U_G_0s: &[secp256k1::Point],
        U_G_1s: &[secp256k1::Point],
        U_H_0s: &[ed25519::Point],
        U_H_1s: &[ed25519::Point],
    ) -> Scalar {
        let mut hasher = Sha256::default();

        for (i, (C_G_i, C_H_i)) in C_G_is.iter().zip(C_H_is.iter()).enumerate() {
            hasher.update(C_G_i.to_bytes());
            hasher.update(C_H_i.compress().as_bytes());
            hasher.update(U_G_0s[i].to_bytes());
            hasher.update(U_G_1s[i].to_bytes());
            hasher.update(U_H_0s[i].compress().as_bytes());
            hasher.update(U_H_1s[i].compress().as_bytes());
        }

        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_slice());

        Scalar::from(bytes)
    }

    pub fn verify(
        &self,
        xG_prime: &secp256k1::Point<Jacobian>,
        xH_prime: ed25519::Point,
    ) -> Result<(), Error> {
        if !secp256k1::verify_bit_commitments_represent_dleq_commitment(
            &self.C_G_is,
            xG_prime,
            &self.r,
        ) {
            return Err(Error::Secp256k1BitCommitmentRepresentation);
        }

        if !ed25519::verify_bit_commitments_represent_dleq_commitment(
            &self.C_H_is,
            xH_prime,
            self.s,
        ) {
            return Err(Error::Ed25519BitCommitmentRepresentation);
        }

        let c = Self::compute_challenge(
            &self
                .C_G_is
                .clone()
                .into_iter()
                .map(Mark::mark::<Normal>)
                .collect::<Vec<_>>(),
            &self.C_H_is,
            &self.U_G_0s,
            &self.U_G_1s,
            &self.U_H_0s,
            &self.U_H_1s,
        );

        for (i, (C_G_i, C_H_i)) in self.C_G_is.iter().zip(self.C_H_is.iter()).enumerate() {
            let c_0 = self.c_0s[i];
            let c_1 = self.c_1s[i];

            if c != c_0 + c_1 {
                return Err(Error::ChallengeSum);
            }

            let res_G_0 = &self.res_G_0s[i];
            let res_G_1 = &self.res_G_1s[i];
            let res_H_0 = self.res_H_0s[i];
            let res_H_1 = self.res_H_1s[i];

            let U_G_0 = &self.U_G_0s[i];
            let U_G_1 = &self.U_G_1s[i];
            let U_H_0 = self.U_H_0s[i];
            let U_H_1 = self.U_H_1s[i];

            if g!(res_G_0 * G) != g!(U_G_0 + { c_0.into_secp256k1() } * C_G_i)
                || g!(res_G_1 * G) != g!(U_G_1 + { c_1.into_secp256k1() } * (C_G_i - G_PRIME))
                || res_H_0 * H != U_H_0 + c_0.into_ed25519() * C_H_i
                || res_H_1 * H != U_H_1 + c_1.into_ed25519() * (C_H_i - *H_PRIME)
            {
                return Err(Error::ResponseVerification);
            }
        }

        Ok(())
    }
}

pub enum Error {
    ChallengeSum,
    ResponseVerification,
    Secp256k1BitCommitmentRepresentation,
    Ed25519BitCommitmentRepresentation,
}

#[cfg(test)]
mod proptest {
    use super::*;
    use ::proptest::prelude::*;

    prop_compose! {
        pub fn scalar()(
            bytes in any::<[u8; 32]>(),
        ) -> Scalar {
            Scalar::from(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::proptest::prelude::*;
    use bigint::U256;
    use ecdsa_fun::fun::marker::Normal;
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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn cross_group_dleq_proof_is_valid(
            x in proptest::scalar(),
        ) {
            let xG_prime = g!({ x.into_secp256k1() } * G_PRIME);
            let xH_prime = x.into_ed25519() * *H_PRIME;

            let proof = Proof::new(&mut thread_rng(), &x);

            assert!(proof.verify(&xG_prime, xH_prime).is_ok());
        }
    }
}
