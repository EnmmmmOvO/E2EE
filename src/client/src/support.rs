use std::error::Error;
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use ring::signature::{UnparsedPublicKey, ED25519};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use crate::util::{
    INTERMEDIATE_KEY_CONSTANT, 
    MESSAGE_KEY_CONSTANT, 
    RECV_KEY_CONSTANT, 
    RECV_SEND_KEY_CONSTANT, 
    ROOT_KEY_CONSTANT, 
    SEND_KEY_CONSTANT
};

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

pub fn hkdf_ratchet_update(root: &mut[u8; 32]) -> Result<[u8; 32], Box<dyn Error>> {
    let hk = Hkdf::<Sha256>::new(Some(root), &[]);
    let mut new_root = [0u8; 32];
    
    hk.expand(RECV_SEND_KEY_CONSTANT, root)
        .map_err(|e| format!("Failed to expand root key: {}", e))?;
    hk.expand(MESSAGE_KEY_CONSTANT, &mut new_root)
        .map_err(|e| format!("Failed to expand message key: {}", e))?;
    
    Ok(new_root)
}

pub fn dh_ratchet_update(shared_key: &[u8; 32], root_key: &mut[u8; 32], reverse: bool) -> Result<([u8; 32], [u8; 32]), Box<dyn Error>> {
    let salt = Hkdf::<Sha256>::new(Some(root_key), shared_key);
    
    let mut intermediate_key = [0u8; 32];
    let mut recv_key = [0u8; 32];
    let mut send_key = [0u8; 32];
    
    salt.expand(RECV_KEY_CONSTANT, &mut recv_key)
        .map_err(|e| format!("Failed to expand send key: {}", e))?;
    
    salt.expand(INTERMEDIATE_KEY_CONSTANT, &mut intermediate_key)
        .map_err(|e| format!("Failed to expand intermediate key: {}", e))?;
    
    let intermediate_salt = Hkdf::<Sha256>::new(Some(&intermediate_key), shared_key);
    
    
    
    intermediate_salt.expand(ROOT_KEY_CONSTANT, root_key)
        .map_err(|e| format!("Failed to expand new root key: {}", e))?;
    
    intermediate_salt.expand(SEND_KEY_CONSTANT, &mut send_key)
        .map_err(|e| format!("Failed to expand recv key: {}", e))?;

    if reverse {
        Ok((send_key, recv_key))
    } else {
        Ok((recv_key, send_key))
    }
}

pub fn verify_spk_signature(ikp_public: &[u8], spk: &[u8], spk_sig: &[u8]) -> Result<(), Box<dyn Error>> {
    let public_key = UnparsedPublicKey::new(&ED25519, ikp_public);
    if ikp_public.len() == 32 { return Ok(()); }
    public_key.verify(spk, spk_sig).map_err(|e| format!("Failed to verify signature: {}", e))?;
    Ok(())
}
