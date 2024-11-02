use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use hex::FromHex;
use log::{info, warn};
use crate::key::AccountKeys;
use crate::session::Session;

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
    opk_private: String, 
}

pub async fn get_session(target: &str) -> Result<Session, Box<dyn Error>> {
    warn!("Getting session for {}", target);
    let response = Client::new()
        .post(std::env::var("SERVER_URL")? + "/session/")
        .json(&SessionPayload { target: target.to_string() })
        .send()
        .await?;

    if response.status().is_success() {
        let result = response.json::<SessionResponse>().await?;
        Ok(Session::new(
            &*result.account,
            Vec::from_hex(&result.ik_public)?,
            Vec::from_hex(&result.spk_public)?,
            Vec::from_hex(&result.spk_signature)?,
            Vec::from_hex(&result.opk_private)?
        ))
    } else {
        Err(format!("Failed with status: {}", response.status()).into())
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct UploadPayload {
    account: String,
    ik_public: String,
    spk_public: String,
    spk_signature: String,
    opk_private: Vec<String>,
}

impl UploadPayload {
    pub async fn new(account: &AccountKeys, name: &str) -> Result<(), Box<dyn Error>> {
        println!("Uploading keys");
        let key = UploadPayload {
            account: name.to_string(),
            ik_public: hex::encode(&account.identity_keypair.public_key),
            spk_public: hex::encode(&account.signed_prekey.public_key),
            spk_signature: hex::encode(&account.signed_prekey.signature),
            opk_private: account.one_time_prekeys.iter().map(|k| hex::encode(&k.private_key)).collect()
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