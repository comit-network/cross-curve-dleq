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
