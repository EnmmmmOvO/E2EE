use std::error::Error;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use crate::file::LocalKey;
use crate::socket::UploadPayload;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountKeys {
    pub identity_keypair: IdentityKeyPair,
    pub signed_prekey: SignedPreKeyPair,
    pub one_time_prekeys: Vec<PreKey>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IdentityKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedPreKeyPair {
    pub(crate) id: u32,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreKey {
    pub id: u32,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl AccountKeys {
    pub async fn new(account: &str) -> Result<Self, Box<dyn Error>> {
        let rng = SystemRandom::new();
        
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| format!("Failed to generate keypair: {}", e))?;
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|e| format!("Failed to generate keypair: {}", e))?;
        
        let identity_keypair = IdentityKeyPair {
            private_key: pkcs8.as_ref().to_vec(),
            public_key: keypair.public_key().as_ref().to_vec(),
        };
        
        let key = AccountKeys {
            signed_prekey: Self::generate_signed_prekey(&identity_keypair, &rng, 1)?,
            one_time_prekeys: (2..=101).map(|id| Self::generate_prekey(&rng, id)).collect::<Result<Vec<_>, _>>()?,
            identity_keypair,
        };
        
        LocalKey::save(&key, &account)?;
        UploadPayload::new(&key, &account).await?;
        
        Ok(key)
    }
    
    fn generate_signed_prekey(
        identity_keypair: &IdentityKeyPair,
        rng: &SystemRandom,
        id: u32,
    ) -> Result<SignedPreKeyPair, Box<dyn Error>> {
        let prekey_pkcs8 = Ed25519KeyPair::generate_pkcs8(rng)
            .map_err(|e| format!("Failed to generate prekey: {}", e))?;
        let prekey_keypair = Ed25519KeyPair::from_pkcs8(prekey_pkcs8.as_ref())
            .map_err(|e| format!("Failed to generate prekey: {}", e))?;
        
        let identity_signing_key = Ed25519KeyPair::from_pkcs8(&identity_keypair.private_key)
            .map_err(|e| format!("Failed to generate prekey: {}", e))?;
        let signature = identity_signing_key.sign(prekey_keypair.public_key().as_ref());

        Ok(SignedPreKeyPair {
            id,
            private_key: prekey_pkcs8.as_ref().to_vec(),
            public_key: prekey_keypair.public_key().as_ref().to_vec(),
            signature: signature.as_ref().to_vec(),
        })
    }

    fn generate_prekey(rng: &SystemRandom, id: u32) -> Result<PreKey, Box<dyn Error>> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng)
            .map_err(|e| format!("Failed to generate prekey: {}", e))?;
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|e| format!("Failed to generate prekey: {}", e))?;
        
        Ok(PreKey {
            id,
            private_key: pkcs8.as_ref().to_vec(),
            public_key: keypair.public_key().as_ref().to_vec(),
        })
    }
    
    pub fn load(account: &str) -> Result<Self, Box<dyn Error>> { Ok(LocalKey::load(account)?) }
}