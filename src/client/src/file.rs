use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::Path;
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::key::{AccountKeys, IdentityKeyPair, PreKey, SignedPreKeyPair};

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalKey {
    ik_private: String,
    ik_public: String,
    spk_private: String,
    spk_public: String,
    spk_signature: String,
    opk_private: Vec<String>,
}

impl LocalKey {
    pub fn new(account: &AccountKeys, path: &str) -> Result<(), Box<dyn Error>> {
        let json = LocalKey {
            ik_private: hex::encode(&account.identity_keypair.private_key),
            ik_public: hex::encode(&account.identity_keypair.public_key),
            spk_private: hex::encode(&account.signed_prekey.private_key),
            spk_public: hex::encode(&account.signed_prekey.public_key),
            spk_signature: hex::encode(&account.signed_prekey.signature),
            opk_private: account.one_time_prekeys.iter().map(|k| hex::encode(&k.private_key)).collect()
        };
        
        let folder_path = Path::new(&std::env::var("BACKUP_PATH")?).join(path);
        fs::create_dir_all(&folder_path)?;
        
        let file = File::create(folder_path.join("keys.json"))?;
        serde_json::to_writer_pretty(file, &json)?;
        
        Ok(())
    }
    
    pub fn from(account: &str) -> Result<AccountKeys, Box<dyn Error>> {
        let json: LocalKey = serde_json::from_reader(
            File::open(std::env::var("BACKUP_PATH")? + account + "/keys.json")?
        )?;
        
        Ok(AccountKeys {
            identity_keypair: IdentityKeyPair {
                private_key: hex::decode(json.ik_private)?,
                public_key: hex::decode(json.ik_public)?,
            },
            signed_prekey: SignedPreKeyPair {
                id: 1,
                private_key: hex::decode(json.spk_private)?,
                public_key: hex::decode(json.spk_public)?,
                signature: hex::decode(json.spk_signature)?,
            },
            one_time_prekeys: json.opk_private.iter()
                .map(|k| hex::decode(k)).collect::<Result<Vec<_>, _>>()?
                .iter()
                .enumerate()
                .map(|(i, k)| PreKey { 
                    id: i as u32, 
                    private_key: k.clone(), 
                    public_key: vec![], 
                }).collect(),
        })
    }
}
