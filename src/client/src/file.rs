use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex};
use glob::glob;
use log::info;
use serde::{Deserialize, Serialize};
use crate::account::Account;
use crate::key::{AccountKeys, IdentityKeyPair, OneTimePreKey, SignedPreKeyPair};
use crate::session::Session;
use crate::support::{string_to_v32, v32};

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
pub struct OPKLocal {
    key: String,
    id: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalKey {
    ik_private: String,
    ik_public: String,
    spk_private: String,
    spk_public: String,
    spk_signature: String,
    opk: Vec<OPKLocal>,
}

impl LocalKey {
    pub fn save(account: &AccountKeys, path: &str) -> Result<(), Box<dyn Error>> {
        let json = LocalKey {
            ik_private: hex::encode(&account.identity_keypair.private_key),
            ik_public: hex::encode(&account.identity_keypair.public_key),
            spk_private: hex::encode(&account.signed_prekey.private_key),
            spk_public: hex::encode(&account.signed_prekey.public_key),
            spk_signature: hex::encode(&account.signed_prekey.signature),
            opk: account.one_time_prekeys.iter().map(|k| OPKLocal {
                key: hex::encode(&k.key),
                id: k.id,
            }).collect(),
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
                private_key: v32(hex::decode(json.ik_private)?)?,
                public_key: v32(hex::decode(json.ik_public)?)?,
            },
            signed_prekey: SignedPreKeyPair {
                private_key: v32(hex::decode(json.spk_private)?)?,
                public_key: v32(hex::decode(json.spk_public)?)?,
                signature: hex::decode(json.spk_signature)?,
            },
            one_time_prekeys: json.opk.iter().map(|k| OneTimePreKey {
                id: k.id,
                key: string_to_v32(&k.key).unwrap(),
            }).collect(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionKey {
    pub send_chain_key: String,
    pub recv_chain_key: String,
    pub root_key: String,
}

impl SessionKey {
    pub fn save(session: &Session, account: &str) -> Result<(), Box<dyn Error>> {
        let json = SessionKey {
            send_chain_key: hex::encode(&session.send_chain_key),
            recv_chain_key: hex::encode(&session.recv_chain_key),
            root_key: hex::encode(&session.root_key),
        };
        
        let folder_path = Path::new(&std::env::var("BACKUP_PATH")?).join(account).join(&session.target);
        fs::create_dir(&folder_path)?;
        
        let file = File::create(folder_path.join("key.json"))?;
        serde_json::to_writer_pretty(file, &json)?;
        
        Ok(())
    }
    
    pub fn overload(session: &Session, account: &str) -> Result<(), Box<dyn Error>> {
        let json = SessionKey {
            send_chain_key: hex::encode(&session.send_chain_key),
            recv_chain_key: hex::encode(&session.recv_chain_key),
            root_key: hex::encode(&session.root_key),
        };
        
        let folder_path = Path::new(&std::env::var("BACKUP_PATH")?).join(account).join(&session.target);
        
        let file = File::create(folder_path.join("key.json"))?;
        serde_json::to_writer_pretty(file, &json)?;
        
        Ok(())
    }
    
    pub fn load(path: &str, account: Arc<Mutex<Option<Account>>>) -> Result<Session, Box<dyn Error>> {
        let json: SessionKey = serde_json::from_reader(
            File::open(
                std::env::var("BACKUP_PATH")? 
                    + account.lock().unwrap().as_ref().unwrap().name() 
                    + "/" + path + "/key.json"
            )?
        )?;
        
        Ok(Session::load(
            path,
            string_to_v32(&json.root_key)?,
            string_to_v32(&json.send_chain_key)?,
            string_to_v32(&json.recv_chain_key)?,
        ))
    }
}
