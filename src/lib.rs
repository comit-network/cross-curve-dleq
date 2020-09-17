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
use bigint::U256;
use bit_vec::BitVec;
use ecdsa_fun::fun::{
    marker::{Jacobian, NonZero, Normal},
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

    /// Bit representation of the scalar.
    ///
    /// The vector of bits is ordered from least significant bit to
    /// most significant bit.
    fn bits(&self) -> BitVec {
        // We reverse the vector of bits to ensure that the bits are
        // ordered from LSB to MSB.
        BitVec::from_bytes(&self.0).iter().rev().collect()
    }

    // TODO: This is always 256 bits, so we could produce an array of that
    // size instead of a vector.

    // TODO: Return tuple of two types of bit opening instead?

    /// Generate openings for Pedersen Commitments to each bit on both
    /// secp256k1 and ed25519.
    pub fn bit_openings<R: RngCore + CryptoRng>(&self, rng: &mut R) -> BitOpenings {
        self.bits()
            .iter()
            .map(|bit| {
                (
                    BitOpening::<secp256k1::Scalar>::new(rng, bit),
                    BitOpening::<ed25519::Scalar>::new(rng, bit),
                )
            })
            .collect::<BitOpenings>()
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

pub type BitOpenings = Vec<(BitOpening<secp256k1::Scalar>, BitOpening<ed25519::Scalar>)>;
pub type BitCommitments = Vec<(
    BitCommitment<secp256k1::Point<Jacobian>>,
    BitCommitment<ed25519::Point>,
)>;

/// Calculate sum of `blinder_i * 2^i`, where `i` is the bit index.
pub fn blinder_sums(openings: BitOpenings) -> (secp256k1::Scalar, ed25519::Scalar) {
    let two = U256::from(2u8);

    let r_total = openings
        .iter()
        .map(|(secp256k1, _)| secp256k1)
        .enumerate()
        .fold(
            secp256k1::Scalar::zero(),
            |acc, (i, BitOpening { blinder: r, .. })| {
                let exp = two.pow(U256::from(i));
                let exp = secp256k1::Scalar::from_bytes(exp.into()).unwrap();

                s!(acc + exp * r)
            },
        )
        .mark::<NonZero>()
        .expect("non-zero r_total");

    let s_total = openings
        .iter()
        .map(|(_, ed25519)| ed25519)
        .enumerate()
        .fold(
            ed25519::Scalar::zero(),
            |acc, (i, BitOpening { blinder: s, .. })| {
                let exp = two.pow(U256::from(i));
                let exp = ed25519::Scalar::from_bytes_mod_order(exp.into());

                acc + exp * s
            },
        );

    (r_total, s_total)
}

/// The opening to a Pedersen Commitment to the value of a bit.
#[derive(Clone, Copy)]
pub struct BitOpening<S> {
    bit: bool,
    blinder: S,
}

#[derive(Debug, Clone, Copy)]
pub struct BitCommitment<P>(P);

impl BitOpening<secp256k1::Scalar> {
    fn new<R: RngCore + CryptoRng>(rng: &mut R, bit: bool) -> Self {
        let blinder = secp256k1::Scalar::random(rng);

        Self { bit, blinder }
    }

    fn commit(&self) -> BitCommitment<secp256k1::Point<Jacobian>> {
        let b = bit_as_secp256k1_scalar(self.bit);
        let r = self.blinder.clone();

        BitCommitment(
            g!(b * G_PRIME + r * G)
                .mark::<NonZero>()
                .expect("r to be non-zero"),
        )
    }
}

fn bit_as_secp256k1_scalar(bit: bool) -> secp256k1::Scalar<Secret, Zero> {
    if bit {
        secp256k1::Scalar::one().mark::<Zero>()
    } else {
        secp256k1::Scalar::zero()
    }
}

impl BitOpening<ed25519::Scalar> {
    fn new<R: RngCore + CryptoRng>(rng: &mut R, bit: bool) -> Self {
        let blinder = ed25519::Scalar::random(rng);

        Self { bit, blinder }
    }

    fn commit(&self) -> BitCommitment<ed25519::Point> {
        let b = bit_as_ed25519_scalar(self.bit);
        let s = self.blinder;

        BitCommitment(b * *H_PRIME + s * H)
    }
}

fn bit_as_ed25519_scalar(bit: bool) -> ed25519::Scalar {
    if bit {
        ed25519::Scalar::one()
    } else {
        ed25519::Scalar::zero()
    }
}

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
    c_0s: Vec<Scalar>,
    c_1s: Vec<Scalar>,
    U_G_0s: Vec<secp256k1::Point>,
    U_H_0s: Vec<ed25519::Point>,
    U_G_1s: Vec<secp256k1::Point>,
    U_H_1s: Vec<ed25519::Point>,
    res_G_0s: Vec<secp256k1::Scalar>,
    res_H_0s: Vec<ed25519::Scalar>,
    res_G_1s: Vec<secp256k1::Scalar>,
    res_H_1s: Vec<ed25519::Scalar>,
}

pub fn cross_group_dleq_prove<R: RngCore + CryptoRng>(rng: &mut R, openings: BitOpenings) -> Proof {
    let n_bits = openings.len();

    let mut C_Gs = Vec::new();
    let mut C_Hs = Vec::new();

    let mut c_cheats = Vec::new();

    let mut U_G_0s = Vec::new();
    let mut U_H_0s = Vec::new();
    let mut U_G_1s = Vec::new();
    let mut U_H_1s = Vec::new();

    let mut res_G_0s = Vec::new();
    let mut res_H_0s = Vec::new();
    let mut res_G_1s = Vec::new();
    let mut res_H_1s = Vec::new();

    for (BitOpening { bit: b, blinder: r }, BitOpening { blinder: s, .. }) in
        openings.clone().into_iter()
    {
        // Compute commitment corresponding to each opening
        let C_G = BitOpening { bit: b, blinder: r }.commit().0;
        let C_H = BitOpening { bit: b, blinder: s }.commit().0;

        // We prove knowledge of the discrete log of C_{G,H} - b{G,H}
        // with respect to {G,H}, proving that it was in fact a
        // commitment to b and proving knowledge of the blinder {r,s}
        let rG_prime = {
            let b = bit_as_secp256k1_scalar(!b);
            g!(C_G - b * G_PRIME)
        };
        let sH_prime = {
            let b = bit_as_ed25519_scalar(!b);
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

        C_Gs.push(C_G);
        C_Hs.push(C_H);

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

    // TODO: Extract into function which will also be used when verifying
    let c = {
        let mut hasher = Sha256::default();

        for i in 0..n_bits {
            hasher.update(C_Gs[i].clone().mark::<Normal>().to_bytes());
            hasher.update(C_Hs[i].compress().as_bytes());
            hasher.update(U_G_0s[i].clone().mark::<Normal>().to_bytes());
            hasher.update(U_G_1s[i].clone().mark::<Normal>().to_bytes());
            hasher.update(U_H_0s[i].compress().as_bytes());
            hasher.update(U_H_1s[i].compress().as_bytes());
        }

        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_slice());

        Scalar::from(bytes)
    };

    let mut c_0s = Vec::new();
    let mut c_1s = Vec::new();

    for (i, (BitOpening { bit: b, blinder: r }, BitOpening { blinder: s, .. })) in
        openings.into_iter().enumerate()
    {
        if b {
            let c_0 = c_cheats[i];
            let c_1 = c - c_0;

            res_G_1s[i] = s!({ res_G_1s[i].clone() } + { c_1.into_secp256k1() } * r)
                .mark::<NonZero>()
                .expect("non-zero response");
            res_H_1s[i] += c_1.into_ed25519() * s;

            c_0s.push(c_0);
            c_1s.push(c_1);
        } else {
            let c_1 = c_cheats[i];
            let c_0 = c - c_1;

            res_G_0s[i] = s!({ res_G_0s[i].clone() } + { c_0.into_secp256k1() } * r)
                .mark::<NonZero>()
                .expect("non-zero response");
            res_H_0s[i] += c_0.into_ed25519() * s;

            c_0s.push(c_0);
            c_1s.push(c_1);
        };
    }

    Proof {
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
    }
}

pub fn verify_bit_commitments_represent_dleq_commitments(
    bit_commitments: BitCommitments,
    blinder_sums: (secp256k1::Scalar, ed25519::Scalar),
    dleq_commitments: (secp256k1::Point<Jacobian>, ed25519::Point),
) -> bool {
    let (r_total, s_total) = blinder_sums;
    let (xG, xH) = dleq_commitments;

    let two = U256::from(2u8);

    let C_G_total = bit_commitments
        .iter()
        .map(|(secp256k1, _)| secp256k1)
        .enumerate()
        .fold(
            secp256k1::Point::zero().mark::<Jacobian>(),
            |acc, (i, BitCommitment(C_G))| {
                let exp = two.pow(U256::from(i));
                let exp = secp256k1::Scalar::<Secret, Zero>::from_bytes(exp.into()).unwrap();

                g!(acc + exp * C_G)
            },
        );

    let C_H_total = bit_commitments
        .iter()
        .map(|(_, ed25519)| ed25519)
        .enumerate()
        .fold(
            ed25519::Scalar::zero() * H,
            |acc, (i, BitCommitment(C_H))| {
                let exp = two.pow(U256::from(i));
                let exp = ed25519::Scalar::from_bytes_mod_order(exp.into());

                acc + exp * C_H
            },
        );

    g!(C_G_total - r_total * G) == xG && C_H_total - s_total * H == xH
}

pub enum ProofVerificationError {
    ChallengeSum,
    Response,
}

pub fn verify_cross_group_dleq_proof(
    commitments: BitCommitments,
    proof: Proof,
) -> Result<(), ProofVerificationError> {
    let n_bits = commitments.len();

    let c = {
        let mut hasher = Sha256::default();

        for i in 0..n_bits {
            hasher.update((commitments[i].0).0.clone().mark::<Normal>().to_bytes());
            hasher.update((commitments[i].1).0.compress().as_bytes());
            hasher.update(proof.U_G_0s[i].clone().mark::<Normal>().to_bytes());
            hasher.update(proof.U_G_1s[i].clone().mark::<Normal>().to_bytes());
            hasher.update(proof.U_H_0s[i].compress().as_bytes());
            hasher.update(proof.U_H_1s[i].compress().as_bytes());
        }

        let hash = hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.as_slice());

        Scalar::from(bytes)
    };

    for i in 0..n_bits {
        let c_0 = proof.c_0s[i];
        let c_1 = proof.c_1s[i];

        if c != c_0 + c_1 {
            return Err(ProofVerificationError::ChallengeSum);
        }

        let res_G_0 = proof.res_G_0s[i].clone();
        let res_G_1 = proof.res_G_1s[i].clone();
        let res_H_0 = proof.res_H_0s[i];
        let res_H_1 = proof.res_H_1s[i];

        let U_G_0 = proof.U_G_0s[i].clone();
        let U_G_1 = proof.U_G_1s[i].clone();
        let U_H_0 = proof.U_H_0s[i];
        let U_H_1 = proof.U_H_1s[i];

        let C_G = commitments[i].0.clone().0;
        let C_H = (commitments[i].1).0;

        if g!(res_G_0 * G) != g!(U_G_0 + { c_0.into_secp256k1() } * C_G)
            || g!(res_G_1 * G) != g!(U_G_1 + { c_1.into_secp256k1() } * (C_G - G_PRIME))
            || res_H_0 * H != U_H_0 + c_0.into_ed25519() * C_H
            || res_H_1 * H != U_H_1 + c_1.into_ed25519() * (C_H - *H_PRIME)
        {
            return Err(ProofVerificationError::Response);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigint::U256;
    use ecdsa_fun::fun::marker::Normal;
    use proptest::prelude::*;
    use rand::thread_rng;

    prop_compose! {
        pub fn scalar()(
            bytes in any::<[u8; 32]>(),
        ) -> Scalar {
            Scalar::from(bytes)
        }
    }

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

    proptest::proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn bit_commitments_represent_dleq_commitments(x in scalar()) {
            let xG = g!({ x.into_secp256k1() } * G_PRIME);
            let xH = x.into_ed25519() * *H_PRIME;

            let bit_openings = x.bit_openings(&mut thread_rng());
            let bit_commitments = bit_openings
                .iter()
                .map(|(secp256k1, ed25519)| (secp256k1.commit(), ed25519.commit()))
                .collect();

            let blinder_sums = blinder_sums(bit_openings);

            assert!(verify_bit_commitments_represent_dleq_commitments(
                bit_commitments,
                blinder_sums,
                (xG, xH),
            ));
        }
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn cross_group_dleq_proof_is_valid(
            x in scalar(),
        ) {
            let bit_openings = x.bit_openings(&mut thread_rng());
            let bit_commitments = bit_openings
                .iter()
                .map(|(secp256k1, ed25519)| (secp256k1.commit(), ed25519.commit()))
                .collect();

            let proof = cross_group_dleq_prove(&mut thread_rng(), bit_openings);

            assert!(verify_cross_group_dleq_proof(bit_commitments, proof).is_ok());
        }
    }
}
