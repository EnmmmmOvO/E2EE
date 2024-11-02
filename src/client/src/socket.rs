use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::{Arc, Mutex};
use hex::FromHex;
use log::{info};
use crate::account::Account;
use crate::file::SessionKey;
use crate::key::{AccountKeys, OneTimePreKey};
use crate::session::Session;
use crate::support::string_to_v32;

#[derive(Serialize, Deserialize, Debug)]
struct SearchPayload {
    account: String,
    target: String,
}

pub async fn search(account: &str, target: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let response = Client::new()
        .post(std::env::var("SERVER_URL")? + "/search/")
        .json(&SearchPayload { account: account.to_string(), target: target.to_string() })
        .send()
        .await?;

    if response.status().is_success() {
        let result = response.json::<Vec<String>>().await?;
        Ok(result)
    } else {
        Err(format!("Failed with status: {}", response.status()).into())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct SessionPayload { target: String }

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResponse {
    account: String, 
    ik_public: String,
    spk_public: String,
    spk_signature: String,
    opk: String, 
    id: i32,
}

pub async fn get_session(target: &str, account: Arc<Mutex<Option<Account>>>) -> Result<Session, Box<dyn Error>> {
    let response = Client::new()
        .post(std::env::var("SERVER_URL")? + "/session/")
        .json(&SessionPayload { target: target.to_string() })
        .send()
        .await?;

    if response.status().is_success() {
        let result = response.json::<SessionResponse>().await?;
        
        let session = Session::new(
            &*result.account,
            string_to_v32(&result.ik_public)?,
            string_to_v32(&result.spk_public)?,
            Vec::from_hex(&result.spk_signature)?,
            string_to_v32(&result.opk)?,
            result.id,
            account.clone()
        )?;
        
        SessionKey::save(&session, account.lock().unwrap().as_ref().unwrap().name())?;
        info!("Loaded session for {}", target);
        Ok(session)
    } else {
        Err(format!("Failed with status: {}", response.status()).into())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OPKPayload {
    key: String,
    id: i32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadPayload {
    account: String,
    ik_public: String,
    spk_public: String,
    spk_signature: String,
    opk: Vec<OPKPayload>,
}

impl UploadPayload {
    pub async fn new(account: &AccountKeys, name: &str, opk: Vec<OneTimePreKey>) -> Result<(), Box<dyn Error>> {
        let key = UploadPayload {
            account: name.to_string(),
            ik_public: hex::encode(&account.identity_keypair.public_key),
            spk_public: hex::encode(&account.signed_prekey.public_key),
            spk_signature: hex::encode(&account.signed_prekey.signature),
            opk: opk.iter().map(|k| OPKPayload { key: hex::encode(&k.key), id: k.id, }).collect(),
        };
        
        let response = Client::new()
            .post(std::env::var("SERVER_URL")? + "/create/")
            .json(&key)
            .send()
            .await?;

        if response.status().is_success() {
            info!("Uploaded keys");
            Ok(())
        } else {
            Err(Box::from(format!("Failed to upload: {}", response.status())))
        }
    }
}