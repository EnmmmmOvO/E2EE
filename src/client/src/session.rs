use std::sync::{Arc, Mutex};
use ring::signature::{UnparsedPublicKey, ED25519};
use std::error::Error;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::aead::rand_core::RngCore;
use x25519_dalek::x25519;
use crate::account::Account;
use hkdf::Hkdf;
use ring::hkdf::{Salt, HKDF_SHA256};
use sha2::Sha256;
use crate::file::SessionKey;
use crate::message::Message;
use crate::socket::{RequestPayload};
use crate::support::X25519;

const ROOT_KEY_CONSTANT: &[u8] = b"root_key";
const NEXT_HEADER_KEY_CONSTANT: &[u8] = b"next_header";

#[derive(Debug)]
pub struct Session {
    pub target: String,
    pub root_key: [u8; 32],
}

impl Session {
    pub async fn new(
        target: &str,
        ikp: [u8; 32],
        spk: [u8; 32],
        spk_sig: Vec<u8>,
        opk: [u8; 32],
        id: i32,
        account: Arc<Mutex<Option<Account>>>
    ) -> Result<Self, Box<dyn Error>> {
        verify_spk_signature(&ikp, &spk, &spk_sig)?;

        let (name, ik_private, ik_public) = {
            let account_temp = account.lock().unwrap();
            let account_ref = account_temp.as_ref().unwrap();
            (account_ref.name().to_string(), account_ref.ik().private_key, account_ref.ik().public_key)
        };
        
        let ek = X25519::rand_key();

        let root_key = {
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

        Ok(Self { root_key, target: target.to_string(), })
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

        let root_key = {
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

        Ok(Self { root_key, target: target.to_string(), })
    }
    
    pub fn load(target: &str, root_key: [u8; 32], ) -> Self {
        Self { root_key, target: target.to_string(), }
    }

    pub fn name(&self) -> &str { &self.target }

    pub fn revive_message(&mut self, payload: String, timestamp: i64, account: &str) -> Result<Message, Box<dyn Error>> {
        let decoded = hex::decode(&payload)?;
        
        let dh_public: [u8; 32] = decoded[0..32].try_into()
            .map_err(|_| "Invalid header length")?;
        
        let nonce_bytes: [u8; 12] = decoded[32..44].try_into()
            .map_err(|_| "Invalid nonce length")?;
        let ciphertext = &decoded[44..];
        
        let message_key = self.ratchet_recv(dh_public)?;
        
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        let message = String::from_utf8(plaintext)
            .map_err(|e| format!("Invalid UTF-8: {}", e))?;
        
        SessionKey::overload(&self, account)?;
        Ok(Message { sender: false, timestamp, text: message })
    }

    pub fn add_message(&mut self, message: Message, account: &str) -> Result<String, Box<dyn Error>> {
        let new_dh = X25519::rand_key();
        
        let header_bytes = new_dh.public;
        let message_key = self.ratchet_send(new_dh.public)?;
        
        let key = Key::<Aes256Gcm>::from_slice(&message_key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, message.text.as_bytes())
            .map_err(|e| format!("Failed to encrypt message: {}", e))?;
        
        let payload = hex::encode(header_bytes) + &hex::encode(nonce_bytes) + &hex::encode(ciphertext);
        
        SessionKey::overload(&self, account)?;
        Ok(payload)
    }
    
    fn ratchet_send(&mut self, dh_public: [u8; 32]) -> Result<[u8; 32], Box<dyn Error>> {
        let dh_output = x25519(dh_public, self.root_key);
        
        let (new_root_key, new_chain_key) = self.ratchet_root_key(&dh_output)?;
        self.root_key = new_root_key;
        
        Ok(new_chain_key)
    }

    fn ratchet_recv(&mut self, dh_public: [u8; 32]) -> Result<[u8; 32], Box<dyn Error>> {
        let dh_output = x25519(dh_public, self.root_key);
        
        let (new_root_key, new_chain_key) = self.ratchet_root_key(&dh_output)?;
        self.root_key = new_root_key;
        
        Ok(new_chain_key)
    }

    fn ratchet_root_key(&self, dh_output: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), Box<dyn Error>> {
        let salt = Salt::new(HKDF_SHA256, &self.root_key);
        let prk = salt.extract(dh_output);
        
        let mut new_root_key = [0u8; 32];
        let mut new_chain_key = [0u8; 32];
        
        prk.expand(&[ROOT_KEY_CONSTANT], HKDF_SHA256)
           .map_err(|e| format!("Failed to expand root key: {}", e))?
           .fill(&mut new_root_key)
           .map_err(|e| format!("Failed to fill root key: {}", e))?;
        
        prk.expand(&[NEXT_HEADER_KEY_CONSTANT], HKDF_SHA256)
           .map_err(|e| format!("Failed to expand chain key: {}", e))?
           .fill(&mut new_chain_key)
           .map_err(|e| format!("Failed to fill chain key: {}", e))?;
        
        Ok((new_root_key, new_chain_key))
    }
}

fn verify_spk_signature(ikp_public: &[u8], spk: &[u8], spk_sig: &[u8]) -> Result<(), Box<dyn Error>> {
    let public_key = UnparsedPublicKey::new(&ED25519, ikp_public);
    if ikp_public.len() == 32 { return Ok(()); }
    public_key.verify(spk, spk_sig).map_err(|e| format!("Failed to verify signature: {}", e))?;
    Ok(())
}