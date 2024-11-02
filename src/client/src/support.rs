use std::error::Error;
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::Scalar;
use rand::RngCore;
use rand::rngs::OsRng;

pub struct X25519 {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

pub fn v32(vec: Vec<u8>) -> Result<[u8; 32], Box<dyn Error>> {
    let array: [u8; 32] = vec.try_into().map_err(|_| "Expected a Vec of length 32")?;
    Ok(array)
}

pub fn string_to_v32(s: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let vec = hex::decode(s)?;
    v32(vec)
}

impl X25519 {
    pub fn rand_key() -> Self {
        let mut rng = OsRng;
        let mut private = [0u8; 32];
        rng.fill_bytes(&mut private);

        let private_key = Scalar::from_bytes_mod_order(private);
        let public = (private_key * X25519_BASEPOINT).to_bytes();

        Self { private, public }
    }
}