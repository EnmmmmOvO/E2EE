use std::error::Error;
use rand::RngCore;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

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
        let mut private = [0u8; 32];
        OsRng.fill_bytes(&mut private);

        let secret = StaticSecret::from(private);
        let public_key = PublicKey::from(&secret);

        Self {
            private,
            public: *public_key.as_bytes(),
        }
    }
}