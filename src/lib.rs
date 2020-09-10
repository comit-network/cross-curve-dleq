// curve25519 order: 2^252 + 27742317777372353535851937790883648493
// secp256k1 order: 115792089237316195423570985008687907852837564279074904382605163141518161494337
// curve25519 has the smaller order of the two, so only secret keys modulo curve25519's order will be accepted.

#[cfg(test)]
mod tests {
    use ecdsa_fun::fun::Scalar;
    use rand::thread_rng;

    #[test]
    fn secp256k1_key_from_ed25519_key_produces_same_bytes() {
        let ed25519 = ed25519_dalek::Keypair::generate(&mut thread_rng());
        let ed25519_bytes = ed25519.secret.to_bytes();

        let secp256k1 = Scalar::from_bytes_mod_order(ed25519_bytes);
        let secp256k1_bytes = secp256k1.to_bytes();

        assert_eq!(ed25519_bytes, secp256k1_bytes);
    }
}
