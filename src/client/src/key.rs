use std::error::Error;
use serde::{Deserialize, Serialize};
use crate::file::LocalKey;
use crate::socket::UploadPayload;
use crate::support::X25519;

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
        let temp = X25519::rand_key();
        
        let identity_keypair = IdentityKeyPair {
            private_key: temp.private,
            public_key: temp.public,
        };

        let mut opk = vec![];
        let mut opk_pub = vec![];

        for i in 1..=100 {
            let keypair = X25519::rand_key();

            opk.push(OneTimePreKey { id: i, key: keypair.private, });
            opk_pub.push(OneTimePreKey { id: i, key: keypair.public, });
        }
        
        let key = AccountKeys {
            signed_prekey: Self::generate_signed_prekey()?,
            one_time_prekeys: opk,
            identity_keypair,
        };
        
        LocalKey::save(&key, &account)?;
        UploadPayload::new(&key, &account, opk_pub).await?;
        
        Ok(key)
    }
    
    fn generate_signed_prekey(
        // identity_keypair: &Ed25519KeyPair
    ) -> Result<SignedPreKeyPair, Box<dyn Error>> {
        let keypair = X25519::rand_key();

        Ok(SignedPreKeyPair {
            private_key: keypair.private,
            public_key: keypair.public,
            signature: [1u8; 32].to_vec(),
        })
    }

    
    
    pub fn load(account: &str) -> Result<Self, Box<dyn Error>> { Ok(LocalKey::load(account)?) }
}