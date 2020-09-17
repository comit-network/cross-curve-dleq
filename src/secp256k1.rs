pub use ecdsa_fun::fun::{g, marker, s, Point, Scalar, G};

lazy_static::lazy_static! {
    /// Alternate generator of secp256k1.
    pub static ref G_PRIME: Point =
        Point::from_bytes(hex_literal::hex!(
            "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        ))
        .expect("valid point");
}
