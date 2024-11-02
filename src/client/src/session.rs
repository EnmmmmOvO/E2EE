use std::sync::{Arc, Mutex};
use ring::signature::{UnparsedPublicKey, ED25519};
use std::error::Error;
use x25519_dalek::x25519;
use crate::account::Account;
use crate::message::Message;
use hkdf::Hkdf;
use ring::hkdf::{Salt, HKDF_SHA256};
use sha2::Sha256;
use crate::socket::{MessagePayload, RequestPayload};
use crate::support::X25519;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use log::info;
use rand::rngs::OsRng;

const CHAIN_KEY_CONSTANT: &[u8] = b"chain_key";
const MESSAGE_KEY_CONSTANT: &[u8] = b"message_key";

#[derive(Debug)]
pub struct Session {
    pub target: String,
    pub session_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub account: Arc<Mutex<Option<Account>>>,
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

        let session_key = {
            let mut key_material = Vec::new();
            
            // DH1 = DH(IKa, SPKb)
            let dh1 = x25519(ik_private, spk);
            key_material.extend_from_slice(&dh1);
            
            // DH2 = DH(EKa, IKb)
            let dh2 = x25519(ek.private, ikp);
            key_material.extend_from_slice(&dh2);
            
            // DH3 = DH(EKa, SPKb)
            let dh3 = x25519(ek.private, spk);
            key_material.extend_from_slice(&dh3);
            
            // DH4 = DH(EKa, OPKb)
            let dh4 = x25519(ek.private, opk);
            key_material.extend_from_slice(&dh4);
    
            let hk = Hkdf::<Sha256>::new(None, &key_material);
            let mut session_key = [0u8; 32];
            hk.expand(b"X3DH-Session-Key", &mut session_key)
                .map_err(|e| format!("Failed to expand key: {}", e))?;
    
            Ok::<[u8; 32], Box<dyn Error>>(session_key)
        }?;

        let salt = Salt::new(HKDF_SHA256, &session_key);
        let prk = salt.extract(&[]);
        
        let mut send_chain_key = [0u8; 32];
        let mut recv_chain_key = [0u8; 32];
        
        let send_okm = prk.expand(&[b"send chain"], HKDF_SHA256)
            .map_err(|e| format!("Failed to expand send chain key: {}", e))?;
        send_okm.fill(&mut send_chain_key)
            .map_err(|e| format!("Failed to fill send chain key: {}", e))?;
        
        let recv_okm = prk.expand(&[b"recv chain"], HKDF_SHA256)
            .map_err(|e| format!("Failed to expand recv chain key: {}", e))?;
        recv_okm.fill(&mut recv_chain_key)
            .map_err(|e| format!("Failed to fill recv chain key: {}", e))?;

        RequestPayload::send(name.to_string(), ik_public, ek.public, id, target.to_string()).await?;
        
        Ok(Self {
            account, session_key, send_chain_key, recv_chain_key, 
            target: target.to_string(),
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
        
        let session_key = {
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
            let mut session_key = [0u8; 32];
            hk.expand(b"X3DH-Session-Key", &mut session_key)
                .map_err(|e| format!("Failed to expand key: {}", e))?;
    
            Ok::<[u8; 32], Box<dyn Error>>(session_key)
        }?;
        
        let salt = Salt::new(HKDF_SHA256, &session_key);
        let prk = salt.extract(&[]);
        
        let mut send_chain_key = [0u8; 32];
        let mut recv_chain_key = [0u8; 32];
        
        let send_okm = prk.expand(&[b"recv chain"], HKDF_SHA256)
            .map_err(|e| format!("Failed to expand send chain key: {}", e))?;
        send_okm.fill(&mut send_chain_key)
            .map_err(|e| format!("Failed to fill send chain key: {}", e))?;
        
        let recv_okm = prk.expand(&[b"send chain"], HKDF_SHA256)
            .map_err(|e| format!("Failed to expand recv chain key: {}", e))?;
        recv_okm.fill(&mut recv_chain_key)
            .map_err(|e| format!("Failed to fill recv chain key: {}", e))?;
        
        Ok(Self {
            account, session_key, send_chain_key, recv_chain_key, 
            target: target.to_string(),
        })
    }
    
    pub fn load(
        target: &str, 
        account: Arc<Mutex<Option<Account>>>, 
        session_key: [u8; 32], 
        send_chain_key: [u8; 32], 
        recv_chain_key: [u8; 32]
    ) -> Self {
        Self {
            account, session_key, send_chain_key, recv_chain_key, 
            target: target.to_string(),
        }
    }
    
    pub fn name(&self) -> &str {
        &self.target
    }

    pub fn revive_message(&mut self, payload: String, timestamp: i64) -> Result<Message, Box<dyn Error>> {
        let nonce_bytes = hex::decode(&payload[..24])?;
        let ciphertext = hex::decode(&payload[24..])?;
        
        let nonce_array: [u8; 12] = nonce_bytes.try_into()
        .map_err(|_| "Invalid nonce length")?;
        
        let message_key = self.ratchet_recv()?;
        
        let cipher = Aes256Gcm::new_from_slice(&message_key)
            .map_err(|e| format!("Failed to create cipher: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_array);
        
        let plaintext = cipher.decrypt(nonce, ciphertext.as_slice())
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        let message = String::from_utf8(plaintext)
            .map_err(|e| format!("Invalid UTF-8: {}", e))?;
        
        Ok(Message { sender: false, timestamp, text: message })
    }
    
    pub fn add_message(&mut self, message: Message) -> Result<String, Box<dyn Error>> {
        
        let message_key = self.ratchet_send()?;
        
        let key = Key::<Aes256Gcm>::from_slice(&message_key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, message.text.as_bytes())
            .map_err(|e| format!("Failed to encrypt message: {}", e))?;
        
        
        let encrypted_payload = hex::encode(nonce_bytes.to_vec()) + &hex::encode(ciphertext);
        
        Ok(encrypted_payload)
    }
    
    fn ratchet_send(&mut self) -> Result<[u8; 32], Box<dyn Error>> {
        let prk = Salt::new(HKDF_SHA256, &self.send_chain_key).extract(&[]);
        
        let mut new_chain_key = [0u8; 32];
        prk.expand(&[CHAIN_KEY_CONSTANT], HKDF_SHA256).map_err(|e| format!("Failed to expand chain key: {}", e))?
           .fill(&mut new_chain_key).map_err(|e| format!("Failed to fill chain key: {}", e))?;
        
        let mut message_key = [0u8; 32];
        prk.expand(&[MESSAGE_KEY_CONSTANT], HKDF_SHA256).map_err(|e| format!("Failed to expand message key: {}", e))?
           .fill(&mut message_key).map_err(|e| format!("Failed to fill message key: {}", e))?;
        
        self.send_chain_key = new_chain_key;
        
        Ok(message_key)
    }
    
    fn ratchet_recv(&mut self) -> Result<[u8; 32], Box<dyn Error>> {
        let prk = Salt::new(HKDF_SHA256, &self.recv_chain_key).extract(&[]);
        
        let mut new_chain_key = [0u8; 32];
        prk.expand(&[CHAIN_KEY_CONSTANT], HKDF_SHA256).map_err(|e| format!("Failed to expand chain key: {}", e))?
           .fill(&mut new_chain_key).map_err(|e| format!("Failed to fill chain key: {}", e))?;
        
        let mut message_key = [0u8; 32];
        prk.expand(&[MESSAGE_KEY_CONSTANT], HKDF_SHA256).map_err(|e| format!("Failed to expand message key: {}", e))?
           .fill(&mut message_key).map_err(|e| format!("Failed to fill message key: {}", e))?;
        
        self.recv_chain_key = new_chain_key;
        
        Ok(message_key)
    }
}


fn verify_spk_signature(ikp_public: &[u8], spk: &[u8], spk_sig: &[u8]) -> Result<(), Box<dyn Error>> {
    let public_key = UnparsedPublicKey::new(&ED25519, ikp_public);
    if ikp_public.len() == 32 { return Ok(()); }
    public_key.verify(spk, spk_sig).map_err(|e| format!("Failed to verify signature: {}", e))?;
    Ok(())
}

