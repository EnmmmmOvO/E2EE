use std::error::Error;
use curve25519_dalek::constants::X25519_BASEPOINT;
use rand::rngs::OsRng;
use ring::signature::{Ed25519KeyPair, KeyPair, Signature};
use serde::{Deserialize, Serialize};
use crate::file::LocalKey;
use crate::socket::UploadPayload;
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use ring::rand::SystemRandom;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountKeys {
    pub identity_keypair: IdentityKeyPair,
    pub signed_prekey: SignedPreKeyPair,
    pub one_time_prekeys: Vec<OneTimePreKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityKeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedPreKeyPair {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OneTimePreKey {
    pub id: i32,
    pub key: [u8; 32],
}


impl AccountKeys {
    pub async fn new(account: &str) -> Result<Self, Box<dyn Error>> {
        let mut private_key = [0u8; 32];
        OsRng.fill_bytes(&mut private_key);
        
        let ed_identity_keypair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|e| format!("Failed to generate Ed25519 identity keypair: {}", e))?;
        let ed_identity_keypair = Ed25519KeyPair::from_pkcs8(ed_identity_keypair.as_ref())
            .map_err(|e| format!("Failed to load Ed25519 identity keypair: {}", e))?;
        
        let public_key: [u8; 32] = ed_identity_keypair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| "Failed to convert Ed25519 public key to [u8; 32]")?;
        
        let identity_keypair = IdentityKeyPair { private_key, public_key, };

        let mut opk = vec![];
        let mut opk_pub = vec![];

        for i in 1..=100 {
            let (pkcs8, public_key) = Self::key()?;

            opk.push(OneTimePreKey { id: i, key: pkcs8, });
            opk_pub.push(OneTimePreKey { id: i, key: public_key, });
        }
        
        let key = AccountKeys {
            signed_prekey: Self::generate_signed_prekey(&ed_identity_keypair)?,
            one_time_prekeys: opk,
            identity_keypair,
        };
        
        LocalKey::save(&key, &account)?;
        UploadPayload::new(&key, &account, opk_pub).await?;
        
        Ok(key)
    }
    
    fn generate_signed_prekey(
        identity_keypair: &Ed25519KeyPair
    ) -> Result<SignedPreKeyPair, Box<dyn Error>> {
        let (private_key, public_key) = Self::key()?;
        
        let signature: Signature = identity_keypair.sign(&public_key);

        Ok(SignedPreKeyPair {
            private_key,
            public_key,
            signature: signature.as_ref().to_vec(),
        })
    }

    fn key() -> Result<([u8; 32], [u8; 32]), Box<dyn Error>> {
        let mut rng = OsRng;
        let mut  private_key = [0u8; 32];
        rng.fill_bytes(&mut private_key);
        
        let private = Scalar::from_bytes_mod_order(private_key);
        let public_key = (private * X25519_BASEPOINT).to_bytes();
        
        Ok((private_key, public_key))
    }
    
    pub fn load(account: &str) -> Result<Self, Box<dyn Error>> { Ok(LocalKey::load(account)?) }
}