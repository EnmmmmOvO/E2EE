use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};
use glob::glob;
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use crate::key::{AccountKeys, IdentityKeyPair, PreKey, SignedPreKeyPair};
use crate::session::Session;

pub fn init_load() -> Vec<String> {
    info!("Loading user directories");
    let pattern = std::env::var("BACKUP_PATH").expect("BACKUP_PATH must be set") + "/*";

    let mut users = Vec::new();

    for entry in glob(&pattern).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                if path.is_dir() {
                    let path = path.file_name().unwrap();
                    info!("Found user {:?}", path);
                    users.push(path.to_string_lossy().to_string());
                }
            },
            Err(e) => println!("Error: {:?}", e),
        }
    }

    users
}

pub fn init_load_user(user: &str) -> Vec<String> {
    info!("Loading user directories");
    let pattern = std::env::var("BACKUP_PATH").expect("BACKUP_PATH must be set") + user + "/*";

    let mut users = Vec::new();

    for entry in glob(&pattern).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                if path.is_dir() {
                    let path = path.file_name().unwrap();
                    info!("Found last user {:?}", path);
                    users.push(path.to_string_lossy().to_string());
                }
            },
            Err(e) => println!("Error: {:?}", e),
        }
    }

    users
}

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
    pub fn save(account: &AccountKeys, path: &str) -> Result<(), Box<dyn Error>> {
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
    
    pub fn load(account: &str) -> Result<AccountKeys, Box<dyn Error>> {
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

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionKey {
    ikp: String,
    spk: String,
    spk_sig: String,
    opk: String
}

impl SessionKey {
    pub fn save(session: &Session, account: &str) -> Result<(), Box<dyn Error>> {
        let json = SessionKey {
            ikp: hex::encode(&session.ikp),
            spk: hex::encode(&session.spk),
            spk_sig: hex::encode(&session.spk_sig),
            opk: hex::encode(&session.opk),
        };
        
        let folder_path = Path::new(&std::env::var("BACKUP_PATH")?).join(account).join(&session.target);
        fs::create_dir(&folder_path)?;
        
        let file = File::create(folder_path.join("key.json"))?;
        serde_json::to_writer_pretty(file, &json)?;
        
        Ok(())
    }
    
    pub fn load(path: &str, account: &str) -> Result<Session, Box<dyn Error>> {
        let json: SessionKey = serde_json::from_reader(
            File::open(std::env::var("BACKUP_PATH")? + account + "/" + path + "/key.json")?
        )?;
        
        Ok(Session::new(
            path,
            hex::decode(json.ikp)?,
            hex::decode(json.spk)?,
            hex::decode(json.spk_sig)?,
            hex::decode(json.opk)?,
        ))
    }
}
