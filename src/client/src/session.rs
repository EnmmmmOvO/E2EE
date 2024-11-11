use std::sync::{Arc, Mutex};
use std::error::Error;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::aead::rand_core::RngCore;
use x25519_dalek::x25519;
use crate::account::Account;
use hkdf::Hkdf;
use log::info;
use sha2::Sha256;
use crate::file::SessionKey;
use crate::message::Message;
use crate::socket::{RequestPayload};
use crate::support::{dh_ratchet_update, hkdf_ratchet_update, verify_spk_signature, X25519};
use crate::util::MAX_TIME_UPDATE;

#[derive(Debug)]
pub struct Session {
    pub target: String,
    pub root_key: [u8; 32],
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub ratchet_private: [u8; 32],
    pub ratchet_public: [u8; 32],
    pub last_pub: [u8; 32],
    pub time: i64,
    pub reverse: bool,
    pub check: bool,
    pub record: Vec<[u8; 32]>,
}

impl Session {
    pub async fn new(
        target: &str,
        ikp: [u8; 32],
        spk: [u8; 32],
        spk_sig: Vec<u8>,
        opk: [u8; 32],
        id: i32,
        account: Arc<Mutex<Option<Account>>>,
    ) -> Result<Self, Box<dyn Error>> {
        verify_spk_signature(&ikp, &spk, &spk_sig)?;

        let (name, ik_private, ik_public) = {
            let account_temp = account.lock().unwrap();
            let account_ref = account_temp.as_ref().unwrap();
            (account_ref.name().to_string(), account_ref.ik().private_key, account_ref.ik().public_key)
        };
        
        let ek = X25519::rand_key();

        let mut root_key = {
            let mut key_material = Vec::new();

            let dh1 = x25519(ik_private, spk);
            key_material.extend_from_slice(&dh1);

            let dh2 = x25519(ek.private, ikp);
            key_material.extend_from_slice(&dh2);

            let dh3 = x25519(ek.private, spk);
            key_material.extend_from_slice(&dh3);

            let dh4 = x25519(ek.private, opk);
            key_material.extend_from_slice(&dh4);

            let hk = Hkdf::<Sha256>::new(None, &key_material);
            let mut root_key = [0u8; 32];
            hk.expand(b"X3DH-Root-Key", &mut root_key)
                .map_err(|e| format!("Failed to expand key: {}", e))?;

            Ok::<[u8; 32], Box<dyn Error>>(root_key)
        }?;

        RequestPayload::send(name.to_string(), ik_public, ek.public, id, target.to_string()).await?;
        
        let shared = x25519(ek.private, opk);
        let (recv_key, send_key) = dh_ratchet_update(&shared, &mut root_key, false)?;

        Ok(Self { 
            root_key,
            ratchet_private: ek.private,
            ratchet_public: ek.public,
            target: target.to_string(),
            send_key,
            recv_key,
            last_pub: opk,
            time: 0,
            reverse: false,
            check: true,
            record: Vec::new(),
        })
    }
    
    pub fn from(
        account: Arc<Mutex<Option<Account>>>,
        ikp: [u8; 32],
        ekp: [u8; 32],
        opk_id: i32,
        target: &str
    ) -> Result<Self, Box<dyn Error>> {
        let (ik_private_key, spk_private_key, opk_private_key) = {
            let account_temp = account.lock().unwrap();
            let account_ref = account_temp.as_ref().unwrap();
            match account_ref.find_opk(opk_id) {
                Some(opk) => (
                    account_ref.ik().private_key,
                    account_ref.spk().private_key,
                    opk,
                ),
                None => return Err("Failed to find one-time prekey".into())
            }
        };

        let mut root_key = {
            let mut key_material = Vec::new();

            let dh1 = x25519(spk_private_key, ikp);
            key_material.extend_from_slice(&dh1);

            let dh2 = x25519(ik_private_key, ekp);
            key_material.extend_from_slice(&dh2);

            let dh3 = x25519(spk_private_key, ekp);
            key_material.extend_from_slice(&dh3);

            let dh4 = x25519(opk_private_key, ekp);
            key_material.extend_from_slice(&dh4);

            let hk = Hkdf::<Sha256>::new(None, &key_material);
            let mut root_key = [0u8; 32];
            hk.expand(b"X3DH-Root-Key", &mut root_key)
                .map_err(|e| format!("Failed to expand key: {}", e))?;

            Ok::<[u8; 32], Box<dyn Error>>(root_key)
        }?;
        
        let dh = x25519(opk_private_key, ekp);
        
        let (recv_key, send_key) = dh_ratchet_update(&dh, &mut root_key, true)?;
        

        Ok(Self { 
            root_key,
            ratchet_private: opk_private_key,
            ratchet_public: opk_private_key,
            last_pub: ekp,
            recv_key,
            send_key,
            time: 0,
            reverse: true,
            target: target.to_string(),
            check: true,
            record: Vec::new(),
        })
    }
    
    pub fn load(
        target: &str, 
        root_key: [u8; 32], 
        recv_key: [u8; 32], 
        send_key: [u8; 32], 
        ratchet_private: [u8; 32],
        ratchet_public: [u8; 32],
        last_pub: [u8; 32],
        time: i64, 
        reverse: bool,
        record: Vec<[u8; 32]>,
        check: bool,
    ) -> Self {
        Self { 
            root_key,
            recv_key,
            send_key,
            ratchet_public,
            ratchet_private,
            last_pub,
            time,
            reverse,
            record,
            check,
            target: target.to_string(),
        }
    }

    pub fn name(&self) -> &str { &self.target }

    pub fn revive_message(&mut self, payload: String, timestamp: i64, account: &str) -> Result<Message, Box<dyn Error>> {
        let message = match payload.chars().next() {
            Some('0') => self.recv(hex::decode(&payload[1..])?),
            Some('1') => self.recv_update_initiative(hex::decode(&payload[1..])?),
            Some('2') => self.recv_update_passive(hex::decode(&payload[1..])?),
            _ => Err("Invalid message type".into())
        }?;
        
        SessionKey::overload(&self, account)?;
        Ok(Message { sender: false, timestamp, text: message })
    }

    pub fn add_message(&mut self, message: Message, account: &str) -> Result<String, Box<dyn Error>> {
        let payload = if self.check == false {
            self.send_update_passive(&message)
        } else if self.time >= MAX_TIME_UPDATE {
            self.send_update_initiative(&message)
        } else {
            self.send(&message)
        }?;
        
        SessionKey::overload(&self, account)?;
        Ok(payload)
    }
    
    fn send(&mut self, message: &Message) -> Result<String, Box<dyn Error>> {
        let message_key = hkdf_ratchet_update(&mut self.send_key)?;
        
        let key = Key::<Aes256Gcm>::from_slice(&message_key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, message.text.as_bytes())
            .map_err(|e| format!("Failed to encrypt message: {}", e))?;
        
        self.time += 1;
        
        Ok(format!("{}{}{}", "0", hex::encode(nonce_bytes), hex::encode(ciphertext)))
    }
    
    fn send_update_passive(&mut self, message: &Message) -> Result<String, Box<dyn Error>> {
        let message_key = hkdf_ratchet_update(&mut self.send_key)?;
        
        let key = Key::<Aes256Gcm>::from_slice(&message_key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, message.text.as_bytes())
            .map_err(|e| format!("Failed to encrypt message: {}", e))?;
        
        self.time += 1;
        self.check = true;
        self.record.clear();
        
        Ok(format!(
            "{}{}{}{}",
            "1",
            hex::encode(self.ratchet_public),
            hex::encode(nonce_bytes),
            hex::encode(ciphertext)
        ))
    }
    
    fn send_update_initiative(&mut self, message: &Message) -> Result<String, Box<dyn Error>> {
        self.time = 1;
        
        let ek = X25519::rand_key();
        self.ratchet_private = ek.private;
        self.ratchet_public = ek.public;
        
        let message_key = hkdf_ratchet_update(&mut self.send_key)?;
        
        let key = Key::<Aes256Gcm>::from_slice(&message_key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, message.text.as_bytes())
            .map_err(|e| format!("Failed to encrypt message: {}", e))?;
        
        Ok(format!(
            "{}{}{}{}",
            "2",
            hex::encode(ek.public),
            hex::encode(nonce_bytes),
            hex::encode(ciphertext)
        ))
    }
    
    fn recv_update_initiative(&mut self, decoded: Vec<u8>) -> Result<String, Box<dyn Error>> {
        let dh_public: [u8; 32] = decoded[0..32].try_into()
            .map_err(|_| "Invalid header length")?;
        
        let nonce_bytes: [u8; 12] = decoded[32..44].try_into()
            .map_err(|_| "Invalid nonce length")?;
        let ciphertext = &decoded[44..];
        
        self.check = false;
        self.time = 0;
        
        self.last_pub = dh_public;
        
        let shared = x25519(self.ratchet_private, dh_public);
        let (recv_key, send_key) = dh_ratchet_update(&shared, &mut self.root_key, self.reverse)?;
        self.recv_key = recv_key;
        self.send_key = send_key;
        
        let message_key = hkdf_ratchet_update(&mut self.recv_key)?;
        
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Failed to decrypt message: {}", e))?;
        
        let result = String::from_utf8(plaintext).map_err(|e| format!("Invalid UTF-8: {}", e))?;
        
        Ok(result)
    }

    fn recv_update_passive(&mut self, decoded: Vec<u8>) -> Result<String, Box<dyn Error>> {
        let dh_public: [u8; 32] = decoded[0..32].try_into()
            .map_err(|_| "Invalid header length")?;
        
        let nonce_bytes: [u8; 12] = decoded[32..44].try_into()
            .map_err(|_| "Invalid nonce length")?;
        let ciphertext = &decoded[44..];
        
        let message_key = hkdf_ratchet_update(&mut self.recv_key)?;
        
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let result = match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => {
                String::from_utf8(plaintext)
                    .map_err(|e| Box::new(e) as Box<dyn Error>)
            },
            Err(_) => {
                if self.check == false {
                    for i in 0..self.record.len() {
                        let mut recv_key = self.record[i].clone();
                        let message_key = hkdf_ratchet_update(&mut recv_key)?;

                        let cipher = Aes256Gcm::new_from_slice(&message_key)
                            .map_err(|e| format!("Failed to create cipher: {}", e))?;
                        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                            self.record[i] = recv_key;
                            return String::from_utf8(plaintext)
                                .map_err(|e| Box::new(e) as Box<dyn Error>);
                        }
                    }
                }
                Err(Box::<dyn Error>::from("Decryption failed".to_string()))
            }
        }?;
        
        self.record.push(self.recv_key);
        
        self.check = false;
        self.time = 0;
        
        let ek = X25519::rand_key();
        self.ratchet_private = ek.private;
        self.ratchet_public = ek.public;
        self.last_pub = dh_public;
        
        let shared = x25519(ek.private, dh_public);
        let (recv_key, send_key) = dh_ratchet_update(&shared, &mut self.root_key, self.reverse)?;
        self.recv_key = recv_key;
        self.send_key = send_key;
        
        Ok(result)
    }
    
    fn recv(&mut self, decoded: Vec<u8>) -> Result<String, Box<dyn Error>> {
        let nonce_bytes: [u8; 12] = decoded[0..12].try_into()
            .map_err(|_| "Invalid nonce length")?;
        let ciphertext = &decoded[12..];
        
        let message_key = hkdf_ratchet_update(&mut self.recv_key)?;
        
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        match cipher.decrypt(nonce, ciphertext) {
            Ok(plaintext) => {
                Ok(String::from_utf8(plaintext)
                    .map_err(|e| format!("Invalid UTF-8: {}", e))?)
            },
            Err(_) => {
                if self.check == false {
                    for i in 0..self.record.len() {
                        let mut recv_key = self.record[i].clone();
                        let message_key = hkdf_ratchet_update(&mut recv_key)?;

                        let cipher = Aes256Gcm::new_from_slice(&message_key)
                            .map_err(|e| format!("Failed to create cipher: {}", e))?;
                        if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                            self.record[i] = recv_key;
                            return Ok(String::from_utf8(plaintext)
                                .map_err(|e| format!("Invalid UTF-8: {}", e))?);
                        }
                    }
                }
                Err("Decryption failed".into())
            }
        }
    } 
}

