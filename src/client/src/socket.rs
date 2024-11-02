use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::sync::{Arc, Mutex};
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
            string_to_v32(&result.ik_public).unwrap(),
            string_to_v32(&result.spk_public).unwrap(),
            vec![],
            string_to_v32(&result.opk).unwrap(),
            result.id,
            account.clone()
        ).await?;
        
        SessionKey::save(&session, account.lock().unwrap().as_ref().unwrap().name())?;
        info!("Loaded session for {}", target);
        Ok(session)
    } else {
        Err(format!("Failed with status: {}", response.status()).into())
    }
}

pub async fn get_session_list(account: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let response = Client::new()
        .post(std::env::var("SERVER_URL")? + "/list/session/")
        .json(&SessionPayload { target: account.to_string() })
        .send()
        .await?;

    if response.status().is_success() {
        let session = response.json::<Vec<String>>().await?;
        info!("Find {} sessions", session.len());
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

#[derive(Serialize, Deserialize, Debug)]
pub struct RequestPayload {
    account: String,
    target: String,
    ikp: String,
    ekp: String,
    opk_id: i32,
}

impl RequestPayload {
    pub async fn send(account: String, ikp: [u8; 32], ekp: [u8; 32], opk_id: i32, target: String) -> Result<(), Box<dyn Error>> {
        let response = Client::new()
            .post(std::env::var("SERVER_URL")? + "/create/session/")
            .json(&Self {
                account,
                target,
                ikp: hex::encode(ikp),
                ekp: hex::encode(ekp),
                opk_id,
            })
            .send()
            .await?;

        if response.status().is_success() {
            info!("Sent request");
            Ok(())
        } else {
            Err(Box::from(format!("Failed to send request: {}", response.status())))
        }
    }
    
    pub async fn receive(target: String, account: Arc<Mutex<Option<Account>>>) -> Result<Session, Box<dyn Error>> {
        let name = {
            let account_temp = account.lock().unwrap();
            let account_ref = account_temp.as_ref().unwrap();
            account_ref.name().to_string()
        };
        
        let response = Client::new()
            .post(std::env::var("SERVER_URL")? + "/get/session/")
            .json(&SearchPayload { target: name , account: target.clone() })
            .send()
            .await?;

        if response.status().is_success() {
            info!("Received request");
            let result = response.json::<Self>().await?;
            
            let session = Session::from(
                account.clone(),
                string_to_v32(&result.ikp).unwrap(),
                string_to_v32(&result.ekp).unwrap(),
                result.opk_id,
                &target
            )?;
            
            SessionKey::save(&session, account.lock().unwrap().as_ref().unwrap().name())?;
            info!("Loaded session for {}", target);
            
            Ok(session)
        } else {
            Err(Box::from(format!("Failed to receive request: {}", response.status())))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MessagePayload {
    account: String,
    target: String,
    pub message: String,
    pub timestamp: i64,
}

impl MessagePayload {
    pub async fn send(account: &str, target: &str, message: String, timestamp: i64) -> Result<(), Box<dyn Error>> {
        let response = Client::new()
            .post(std::env::var("SERVER_URL")? + "/create/message/")
            .json(&Self { 
                account: account.to_string(), 
                target: target.to_string(), 
                message, 
                timestamp 
            })
            .send()
            .await?;

        if response.status().is_success() {
            info!("Sent message");
            Ok(())
        } else {
            Err(Box::from(format!("Failed to send message: {}", response.status())))
        }
    }
    
    pub async fn receive(account: String, target: String) -> Result<Vec<MessagePayload>, Box<dyn Error>> {
        let response = Client::new()
            .post(std::env::var("SERVER_URL")? + "/message/")
            .json(&SearchPayload { account, target })
            .send()
            .await?;

        if response.status().is_success() {
            info!("Received message");
            let result = response.json::<Vec<MessagePayload>>().await?;
            Ok(result)
        } else {
            Err(Box::from(format!("Failed to receive message: {}", response.status())))
        }
    }
}