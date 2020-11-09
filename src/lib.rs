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
use ecdsa_fun::{
    fun::{
        marker::{NonZero, Normal},
        s,
    },
    nonce::Deterministic,
    ECDSA,
};
use generic_array::{
    typenum::consts::{U31, U32},
    GenericArray,
};
use rand::{CryptoRng, Rng, RngCore};
use sha2::{Digest, Sha256};
use std::ops::{Add, Sub};

/// A scalar that has the same bit representation for both ed25519 and
/// secp256k1.
///
/// Any valid scalar for ed25519 has the same bit representation for secp256k1,
/// due to the smaller curve order for ed25519 compared to secp256k1. On the
/// other hand, not all valid scalars for secp256k1 have the same bit
/// representation for ed25519.
///
/// Since the order of ed25519 is equal to 2^252 +
/// 0x14def9dea2f79cd65812631a5cf5d3ed, for simplicity we only support 252 bit
/// scalars.
///
/// The underlying array of bytes has a little-endian encoding.
#[cfg_attr(
    feature = "serde",
    serde(crate = "serde_crate"),
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub struct Scalar([u8; 32]);

impl Scalar {
    /// Generate a random 252 bit scalar.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // the first 246 bits can be completely random
        let mut lsbs = [0u8; 31];
        rng.fill_bytes(&mut lsbs);

        // the value of the last 8 bits must be < 16, so that the number can be
        // expressed in a maximum of 252 bits
        let msb = rng.gen_range(0, 15u8);

        let bytes = lsbs
            .iter()
            .copied()
            .chain(std::iter::once(msb))
            .collect::<GenericArray<u8, U32>>();

        Self(bytes.into())
    }

    /// Decompose scalar into a vector of bits with little-endian encoding.
    pub(crate) fn bits(&self) -> BitVec {
        let mut bytes = self.0;

        // `BitVec::from_bytes` expects the bytes that it takes in as an argument to be
        // big-endian
        bytes.reverse();

        // in order to produce a little-endian encoded vector of bits, we reverse the
        // vector
        let bits: BitVec = BitVec::from_bytes(&bytes).iter().rev().collect();

        bits.iter().take(252).collect()
    }

    pub fn into_secp256k1(self) -> secp256k1::Scalar {
        self.into()
    }

    pub fn into_ed25519(self) -> ed25519::Scalar {
        self.into()
    }
}

/// Implement addition for `Scalar`.
impl Add<Scalar> for Scalar {
    type Output = Scalar;
    fn add(self, rhs: Scalar) -> Self::Output {
        let res = self.into_ed25519() + rhs.into_ed25519();

        Scalar(res.to_bytes())
    }
}

/// Implement subtraction for `Scalar`.
impl Sub<Scalar> for Scalar {
    type Output = Scalar;
    fn sub(self, rhs: Scalar) -> Self::Output {
        let res = self.into_ed25519() - rhs.into_ed25519();

        Scalar(res.to_bytes())
    }
}

// TODO: Consider introducing `Commitment` and `Blinder` types.

/// Generate Pedersen Commitment to the value of a bit. Also return the blinder
/// used.
pub trait Commit {
    type Commitment;
    type Blinder;
    fn commit<R: RngCore + CryptoRng>(rng: &mut R, bit: bool) -> (Self::Commitment, Self::Blinder);
}

#[derive(Debug, Clone, Copy)]
struct BitCommitment<P>(P);

impl From<Scalar> for secp256k1::Scalar {
    fn from(from: Scalar) -> Self {
        let mut bytes = from.0;

        // `Scalar`s are little-endian and `secp256k1::Scalar`s are big-endian,
        // so we reverse the bytes
        bytes.reverse();

        secp256k1::Scalar::<Secret, Zero>::from_bytes(bytes)
            .expect("cannot overflow since Scalars are 252 bits long")
            .mark::<NonZero>()
            .expect("non-zero scalar")
    }
}

impl From<Scalar> for ed25519::Scalar {
    fn from(from: Scalar) -> Self {
        ed25519::Scalar::from_bits(from.0)
    }
}

/// Non-interactive zero-knowledge proof of knowledge of the same discrete
/// logarithm across secp256k1 and ed25519.
#[cfg_attr(
    feature = "serde",
    serde(crate = "serde_crate"),
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[derive(Clone, Debug, PartialEq)]
pub struct Proof {
    /// Pedersen Commitments for bits of the secp256k1 scalar.
    ///
    /// Mathematical expression: `b_i * G + r_i * G_PRIME`, where `b_i` is the
    /// `ith` bit, `r_i` is its blinder, and `G` and `G_PRIME` are generators of
    /// secp256k1.
    C_G_is: Vec<secp256k1::Point>,
    /// Pedersen Commitments for bits of the ed25519 scalar.
    ///
    /// Mathematical expression: `b_i * H + s_i * H_PRIME`, where `b_i` is the
    /// `ith` bit, `s_i` is its blinder, and `H` and `H_PRIME` are generators of
    /// secp256k1.
    C_H_is: Vec<ed25519::Point>,
    /// Challenges for proofs that a bit is equal to 0.
    c_0s: Vec<Challenge>,
    /// Challenges for proofs that a bit is equal to 1.
    c_1s: Vec<Challenge>,
    /// Announcements for proofs that a bit of the secp256k1 scalar is equal to
    /// 0.
    U_G_0s: Vec<secp256k1::Point>,
    /// Announcements for proofs that a bit of the ed25519 scalar is equal to 0.
    U_H_0s: Vec<ed25519::Point>,
    /// Announcements for proofs that a bit of the secp256k1 scalar is equal to
    /// 1.
    U_G_1s: Vec<secp256k1::Point>,
    /// Announcements for proofs that a bit of the ed25519 scalar is equal to 0.
    U_H_1s: Vec<ed25519::Point>,
    /// Responses for proofs that a bit of the secp256k1 scalar is equal to 0.
    res_G_0s: Vec<secp256k1::Scalar>,
    /// Responses for proofs that a bit of the ed25519 scalar is equal to 0.
    res_H_0s: Vec<ed25519::Scalar>,
    /// Responses for proofs that a bit of the secp256k1 scalar is equal to 1.
    res_G_1s: Vec<secp256k1::Scalar>,
    /// Responses for proofs that a bit of the ed25519 scalar is equal to 1.
    res_H_1s: Vec<ed25519::Scalar>,
    /// Blinder for the "overall" Pedersen Commitment of the secp256k1 scalar.
    ///
    /// Calculation: sum of `r_i * 2^i`, where `i` is the index of the bit and
    /// `r_i` its blinder.
    r: secp256k1::Scalar,
    /// Blinder for the "overall" Pedersen Commitment of the ed25519 scalar.
    ///
    /// Calculation: sum of `s_i * 2^i`, where `i` is the index of the bit and
    /// `s_i` its blinder.
    s: ed25519::Scalar,
    pi_G: secp256k1::Signature,
    pi_H: ed25519::Signature,
}

impl Proof {
    /// Prove knowledge of `witness` across secp256k1 and ed25519. In other
    /// words, prove knowledge of the value of `witness`, whilst also proving
    /// that it has an equivalent representation on secp256k1 and ed25519.
    ///
    /// # High-level strategy
    ///
    /// 1. Decompose `witness` into bits.
    /// 2. For each bit, generate a Pedersen Commitment of the form
    /// `C_G_i = bit_i * G + r_i * G_PRIME`, where `r_i` is a blinder, and `G`
    /// and `G_PRIME` are generators of secp256k1.
    /// 3. For each bit, also generate a Pedersen Commitment of the form
    /// `C_H_i = bit * H + s_i * H_PRIME`, where `s_i` is a blinder, and `H` and
    /// `H_PRIME` are generators of ed25519.
    /// 4. Leveraging the [_composition of Sigma-protocols_], for every bit
    /// prove knowledge of
    ///
    /// - the discrete logarithm w.r.t. `G_PRIME` of `C_G_i` AND the discrete
    ///   logarithm w.r.t `H_PRIME` of `C_H_i`; OR
    /// - the discrete logarithm w.r.t. `G_PRIME` of `C_G_i - G` AND the
    ///   discrete logarithm w.r.t `H_PRIME` of `C_H_i - H`.
    ///
    /// This proves that each bit is the same, that each Pedersen Commitment is
    /// to either 0 or 1, and knowledge of the corresponding blinders (`r_i` and
    /// `s_i`) for each bit.
    ///
    /// 5. Prove that the sum of all `C_G_i * 2^i` minus `r * G_PRIME` is equal
    /// to the public value `witness * G`, and that the sum of all `C_H_i * 2^i`
    /// minus `s * H_PRIME` is equal to the public value `witness * H`.
    ///
    /// To this end, the proof contains `r` equal to the sum `r_i * 2^i` for all
    /// `i` and the `s` equal to the sum `s_i * 2^i` for all `i`. The verifier
    /// will simply operate as indicated above and verify that the equalities
    /// hold.
    ///
    /// 6. Prove that the public values `witness * G` and `witness * H` are
    /// solely composed of a scalar multiplied by the basepoints `G` and `H`
    /// respectively. This can be achieved by proving knowledge of the discrete
    /// logarithm of the public value w.r.t. the corresponding basepoint, so a
    /// signature per public value suffices.
    ///
    /// [_composition of Sigma-protocols_]: https://www.win.tue.nl/~berry/CryptographicProtocols/LectureNotes.pdf
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
            // compute commitment corresponding to each opening
            let (C_G, r) = secp256k1::PedersenCommitment::commit(rng, b);
            let (C_H, s) = ed25519::PedersenCommitment::commit(rng, b);

            // we prove knowledge of the discrete log of C_{G,H} - b{G_PRIME,H_PRIME} with
            // respect to {G,H}, proving that it was in fact a commitment to b and proving
            // knowledge of the blinder {r,s}
            let rG_prime = {
                let b = secp256k1::bit_as_scalar(!b);
                g!(C_G - b * G)
            };
            let sH_prime = {
                let b = ed25519::bit_as_scalar(!b);
                C_H - &H * &b
            };

            // generate randomness for actual bit w.r.t. secp256k1 and ed25519 groups
            let u_G = secp256k1::Scalar::random(rng);
            let u_H = ed25519::Scalar::random(rng);
            // compute announcement for actual bit w.r.t. secp256k1 and ed25519 groups
            let U_G = g!(u_G * G_PRIME).mark::<Normal>();
            let U_H = u_H * *H_PRIME;

            // randomly generate challenge for the wrong bit
            let c_cheat = Challenge::random(rng);

            // randomly generate responses for wrong bit w.r.t. secp256k1 and ed25519 groups
            let res_G_cheat = secp256k1::Scalar::random(rng);
            let res_H_cheat = ed25519::Scalar::random(rng);
            // build announcements using pre-generated challenge and response w.r.t
            // secp256k1 and ed25519 groups
            let U_G_cheat = {
                let c_cheat = c_cheat.into_secp256k1();
                g!(res_G_cheat * G_PRIME - c_cheat * rG_prime)
                    .mark::<Normal>()
                    .mark::<NonZero>()
                    .expect("non-zero announcement")
            };
            let U_H_cheat = {
                let c_cheat = c_cheat.into_ed25519();
                res_H_cheat * *H_PRIME - c_cheat * sH_prime
            };

            C_G_is.push(C_G);
            r_is.push(r);

            C_H_is.push(C_H);
            s_is.push(s);

            c_cheats.push(c_cheat);

            if b {
                // if the the actual value of the bit is 1, we cheat on the announcement and
                // response for the proof that proves that the value of the bit is 0
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

                // if the the actual value of the bit is 0, we cheat on the announcement and
                // response for the proof that proves that the value of the bit is 1
                U_G_1s.push(U_G_cheat);
                U_H_1s.push(U_H_cheat);
                res_G_1s.push(res_G_cheat);
                res_H_1s.push(res_H_cheat);
            }
        }

        // produce challenge by hashing all the announcements and all the statements
        // (the bitwise Pedersen Commitments). This challenge will then be split by us,
        // the prover, allowing us to "cheat" on one of the proofs per bit i.e. the
        // wrong bit for which we randomly generated the challenge above
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
                // compute challenge for the actual bit
                let c_1 = c - c_0;

                // since we don't control `c_1` the response for these proofs will be legitimate
                res_G_1s[i] = s!({ &res_G_1s[i] } + { c_1.into_secp256k1() } * { &r_is[i] })
                    .mark::<NonZero>()
                    .expect("non-zero response");
                res_H_1s[i] += c_1.into_ed25519() * s_is[i];

                c_0s.push(c_0);
                c_1s.push(c_1);
            } else {
                let c_1 = c_cheats[i];
                // compute challenge for the actual bit
                let c_0 = c - c_1;

                // since we don't control `c_0` the response for these proofs will be legitimate
                res_G_0s[i] = s!({ &res_G_0s[i] } + { c_0.into_secp256k1() } * { &r_is[i] })
                    .mark::<NonZero>()
                    .expect("non-zero response");
                res_H_0s[i] += c_0.into_ed25519() * s_is[i];

                c_0s.push(c_0);
                c_1s.push(c_1);
            };
        }

        // sum of `r_i * 2^i` for all `i`
        let r = secp256k1::blinder_sum(&r_is);
        // sum of `s_i * 2^i` for all `i`
        let s = ed25519::blinder_sum(&s_is);

        // this signature serves as proof that the unblinded sum of the commitments is
        // of the form `x * G`
        let pi_G = {
            let ecdsa = ECDSA::<Deterministic<Sha256>>::default();

            let x = witness.into_secp256k1();
            let X = ecdsa.verification_key_for(&x);

            let pk_hash = Sha256::digest(&X.to_bytes()).into();

            ecdsa.sign(&x, &pk_hash)
        };

        // this signature serves as proof that the unblinded sum of the commitments is
        // of the form `x * H`
        let pi_H = {
            let x = witness.into_ed25519();
            let X = &x * &H;

            let pk_hash: [u8; 32] = Sha256::digest(X.compress().as_bytes()).into();

            ed25519::Signature::new(rng, &x, &pk_hash)
        };

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
            pi_G,
            pi_H,
        }
    }

    /// Compute challenge by hashing the statements (Pedersen Commitments) and
    /// announcements for each bitwise proof.
    fn compute_challenge(
        C_G_is: &[secp256k1::Point<impl secp256k1::PointType>],
        C_H_is: &[ed25519::Point],
        U_G_0s: &[secp256k1::Point],
        U_G_1s: &[secp256k1::Point],
        U_H_0s: &[ed25519::Point],
        U_H_1s: &[ed25519::Point],
    ) -> Challenge {
        let mut hasher = Sha256::default();

        for (i, (C_G_i, C_H_i)) in C_G_is.iter().zip(C_H_is.iter()).enumerate() {
            hasher.update(C_G_i.clone().mark::<Normal>().to_bytes());
            hasher.update(C_H_i.compress().as_bytes());
            hasher.update(U_G_0s[i].to_bytes());
            hasher.update(U_G_1s[i].to_bytes());
            hasher.update(U_H_0s[i].compress().as_bytes());
            hasher.update(U_H_1s[i].compress().as_bytes());
        }

        let hash = hasher.finalize();

        let mut bytes = [0u8; 31];
        bytes.copy_from_slice(&hash.as_slice()[..31]);

        Challenge(bytes)
    }

    /// Verify the proof.
    ///
    /// In particular:
    ///
    /// 1. Ensure that the combinations of Pedersen Commitments actually
    /// represent the public values `xG` and `xH`.
    /// 2. Ensure that the public values `xG` and `xH` actually only have `G`
    /// and `H` components respectively.
    /// 3. Ensure that each bitwise response satisfies its corresponding
    /// challenge.
    pub fn verify(&self, xG: secp256k1::Point, xH: ed25519::Point) -> Result<(), Error> {
        if self.C_G_is.len() != 252
            || self.C_H_is.len() != 252
            || self.c_0s.len() != 252
            || self.c_1s.len() != 252
            || self.U_G_0s.len() != 252
            || self.U_G_1s.len() != 252
            || self.U_H_0s.len() != 252
            || self.U_H_1s.len() != 252
            || self.res_G_0s.len() != 252
            || self.res_G_1s.len() != 252
            || self.res_H_0s.len() != 252
            || self.res_H_1s.len() != 252
        {
            return Err(Error::WrongNumberOfElements);
        }

        // avoid a quirk in ed25519 where some points can be used to produce wildcard
        // signatures. See: https://slowli.github.io/ed25519-quirks/wildcards/
        if !xH.is_torsion_free() {
            return Err(Error::Ed25519TorsionPoint);
        }

        if !secp256k1::verify_bit_commitments_represent_dleq_commitment(&self.C_G_is, &xG, &self.r)
        {
            return Err(Error::Secp256k1BitCommitmentRepresentation);
        }

        let pi_G_is_valid = {
            let ecdsa = ECDSA::verify_only();
            let pk_hash = Sha256::digest(&xG.clone().mark::<Normal>().to_bytes()).into();
            ecdsa.verify(&xG, &pk_hash, &self.pi_G)
        };
        if !pi_G_is_valid {
            return Err(Error::Secp256k1Signature);
        }

        if !ed25519::verify_bit_commitments_represent_dleq_commitment(&self.C_H_is, xH, self.s) {
            return Err(Error::Ed25519BitCommitmentRepresentation);
        }

        let pi_H_is_valid = {
            let pk_hash: [u8; 32] = Sha256::digest(xH.compress().as_bytes()).into();
            self.pi_H.verify(&xH, &pk_hash)
        };
        if !pi_H_is_valid {
            return Err(Error::Ed25519Signature);
        }

        let c = Self::compute_challenge(
            &self.C_G_is,
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

            if g!(res_G_0 * G_PRIME) != g!(U_G_0 + { c_0.into_secp256k1() } * C_G_i)
                || g!(res_G_1 * G_PRIME) != g!(U_G_1 + { c_1.into_secp256k1() } * (C_G_i - G))
                || res_H_0 * *H_PRIME != U_H_0 + c_0.into_ed25519() * C_H_i
                || res_H_1 * *H_PRIME != U_H_1 + c_1.into_ed25519() * (C_H_i - H.basepoint())
            {
                return Err(Error::ResponseVerification);
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("one or more of the arrays included in the proof did not have exactly 252 elements")]
    WrongNumberOfElements,
    #[error("sum of bitwise split challenges not equal to total challenge: c_0 + c_1 != c")]
    ChallengeSum,
    #[error("bitwise response did not satisfy challenge")]
    ResponseVerification,
    #[error("combination of bitwise secp256k1 pedersen commitments not equal to public value")]
    Secp256k1BitCommitmentRepresentation,
    #[error("combination of bitwise ed25519 pedersen commitments not equal to public value")]
    Ed25519BitCommitmentRepresentation,
    #[error("signature failed to prove that secp256k1 public value is of the form x * G")]
    Secp256k1Signature,
    #[error("signature failed to prove that ed25519 public value is of the form x * H")]
    Ed25519Signature,
    #[error("ed25519 public value is a torsion point")]
    Ed25519TorsionPoint,
}

// TODO: Document choice of 31-byte challenge
#[cfg_attr(
    feature = "serde",
    serde(crate = "serde_crate"),
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub struct Challenge([u8; 31]);

impl Challenge {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 31];

        rng.fill_bytes(&mut bytes);

        Self(bytes)
    }

    fn xor(self, rhs: Challenge) -> Self {
        let sum = self
            .0
            .iter()
            .zip(rhs.0.iter())
            .map(|(rhs_byte, lhs_byte)| rhs_byte ^ lhs_byte)
            .collect::<GenericArray<u8, U31>>();

        Challenge(sum.into())
    }
    pub fn into_secp256k1(self) -> secp256k1::Scalar {
        self.into()
    }

    pub fn into_ed25519(self) -> ed25519::Scalar {
        self.into()
    }
}

impl Add<Challenge> for Challenge {
    type Output = Challenge;

    fn add(self, rhs: Challenge) -> Self::Output {
        self.xor(rhs)
    }
}

impl Sub<Challenge> for Challenge {
    type Output = Challenge;

    fn sub(self, rhs: Challenge) -> Self::Output {
        self.xor(rhs)
    }
}

impl From<Challenge> for secp256k1::Scalar {
    fn from(from: Challenge) -> Self {
        let bytes = std::iter::once(0u8)
            .chain(from.0.iter().copied())
            .collect::<GenericArray<u8, U32>>();

        secp256k1::Scalar::<Secret, Zero>::from_bytes_mod_order(bytes.into())
            .mark::<NonZero>()
            .expect("non-zero scalar")
    }
}

impl From<Challenge> for ed25519::Scalar {
    fn from(from: Challenge) -> Self {
        let bytes = from
            .0
            .iter()
            .copied()
            .chain(std::iter::once(0u8))
            .collect::<GenericArray<u8, U32>>();

        Self::from_bytes_mod_order(bytes.into())
    }
}

#[cfg(test)]
mod proptest {
    use super::*;
    use ::proptest::prelude::*;

    // TODO: We use this to generate test data, and I have verified that it is in
    // line with what we do to generate random `Scalar`s, but both functions must be
    // tied together somehow
    prop_compose! {
        pub fn scalar()(
            lsbs in any::<[u8; 31]>(),
            msb in (0..16u8),
        ) -> Scalar {
            let bytes = lsbs.iter().copied()
                .chain(std::iter::once(msb))
                .collect::<GenericArray<u8, U32>>();

            Scalar(bytes.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::proptest::prelude::*;
    use rand::thread_rng;

    proptest! {
        #[test]
        fn secp256k1_key_from_ed25519_key_produces_same_bytes(
            bytes in any::<[u8; 32]>(),
        ) {
            let ed25519 = ed25519::Scalar::from_bytes_mod_order(bytes);
            let ed25519_bytes = ed25519.to_bytes();

            let secp256k1 = secp256k1::Scalar::from_bytes_mod_order(ed25519_bytes);
            let secp256k1_bytes = secp256k1.to_bytes();

            assert_eq!(ed25519_bytes, secp256k1_bytes);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn cross_group_dleq_proof_is_valid(
            x in proptest::scalar(),
        ) {
            let xG = g!({ x.into_secp256k1() } * G).mark::<Normal>();
            let xH = &x.into_ed25519() * &H;

            let proof = Proof::new(&mut thread_rng(), &x);

            assert!(proof.verify(xG, xH).is_ok());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn cross_group_dleq_proof_for_wrong_scalar_is_invalid(
            x in proptest::scalar(),
            y in proptest::scalar(),
        ) {
            let mut rng = thread_rng();

            let xG = g!({ x.into_secp256k1() } * G).mark::<Normal>();
            let xH = &x.into_ed25519() * &H;

            let proof = Proof::new(&mut rng, &y);

            assert!(proof.verify(xG, xH).is_err());
        }
    }
}
