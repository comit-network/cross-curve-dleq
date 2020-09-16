#![allow(non_snake_case)]

use bigint::U256;
use bit_vec::BitVec;
use ecdsa_fun::fun::{
    marker::{Jacobian, NonZero, Normal},
    s,
};
use ed25519::{H, H_PRIME};
use rand::{CryptoRng, RngCore};
use secp256k1::{
    g,
    marker::{Mark, Secret, Zero},
    G, G_PRIME,
};
use sha2::{Digest, Sha256};
use std::ops::{Add, Sub};

mod secp256k1 {
    pub use ecdsa_fun::fun::{g, marker, s, Point, Scalar, G};

    lazy_static::lazy_static! {
        /// Alternate generator of secp256k1.
        pub static ref G_PRIME: Point =
            Point::from_bytes(hex_literal::hex!(
                "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
            ))
            .expect("valid point");
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
#[derive(Clone, Copy)]
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
            .collect::<BitOpenings>()
    }

    pub fn into_secp256k1(self) -> secp256k1::Scalar {
        self.into()
    }

    pub fn into_ed25519(self) -> ed25519::Scalar {
        self.into()
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;
    fn sub(self, rhs: Scalar) -> Self::Output {
        let res = self.into_ed25519() - rhs.into_ed25519();

        Scalar(*res.as_bytes())
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;
    fn add(self, rhs: Scalar) -> Self::Output {
        let res = self.into_ed25519() + rhs.into_ed25519();

        Scalar(*res.as_bytes())
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
            g!(b * G + r * G_PRIME)
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

        BitCommitment(b * H + s * *H_PRIME)
    }
}

fn bit_as_ed25519_scalar(bit: bool) -> ed25519::Scalar {
    if bit {
        ed25519::Scalar::one()
    } else {
        ed25519::Scalar::zero()
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
            let b = bit_as_secp256k1_scalar(b);
            g!(C_G - b * G)
        };
        let sH_prime = {
            let b = bit_as_ed25519_scalar(b);
            C_H - b * H
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

        Scalar(bytes)
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

            res_G_0s[i] = s!({ res_G_1s[i].clone() } + { c_1.into_secp256k1() } * r)
                .mark::<NonZero>()
                .expect("non-zero response");
            res_H_0s[i] += c_1.into_ed25519() * s;

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

    g!(C_G_total - r_total * G_PRIME) == xG && C_H_total - s_total * *H_PRIME == xH
}

pub fn verify_cross_group_dleq_proof(commitments: BitCommitments, proof: Proof) -> bool {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn bit_commitments_represent_dleq_commitments() {
        let x = Scalar::random(&mut thread_rng());
        let xG = g!({ x.into_secp256k1() } * G);
        let xH = x.into_ed25519() * H;

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
