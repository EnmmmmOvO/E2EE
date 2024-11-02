use std::sync::{Arc, Mutex};
use ring::signature::{UnparsedPublicKey, ED25519};
use std::error::Error;
use log::info;
use x25519_dalek::x25519;
use crate::account::Account;
use crate::message::Message;
use hkdf::Hkdf;
use ring::hkdf::{Salt, HKDF_SHA256};
use sha2::Sha256;
use crate::support::X25519;

#[derive(Debug)]
pub struct Session {
    pub target: String,
    pub ikp: [u8; 32],
    pub spk: [u8; 32],
    pub spk_sig: Vec<u8>,
    pub opk: [u8; 32],
    pub session_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub id: i32,
    pub account: Arc<Mutex<Option<Account>>>,
    message: Arc<Mutex<Vec<Message>>>,
}

impl Session {
    pub fn new(
        target: &str,
        ikp: [u8; 32],
        spk: [u8; 32],
        spk_sig: Vec<u8>,
        opk: [u8; 32],
        id: i32,
        account: Arc<Mutex<Option<Account>>>
    ) -> Result<Self, Box<dyn Error>> {
        verify_spk_signature(&ikp, &spk, &spk_sig)?;

        let ik_private_key = {
            let account_temp = account.lock().unwrap();
            let account_ref = account_temp.as_ref().unwrap();
            account_ref.ik().private_key
        };
        
        let ek = X25519::rand_key();

        let session_key = x3dh(
            ikp, spk, opk, ik_private_key, ek.private
        )?;

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
        
        Ok(Self {
            ikp, spk, spk_sig, opk, account, id, session_key, send_chain_key, recv_chain_key, 
            target: target.to_string(),
            message: Arc::new(Mutex::new(vec![]))
        })
    }
    
    pub fn name(&self) -> &str {
        &self.target
    }
    
    pub fn message(&self) -> Arc<Mutex<Vec<Message>>> {
        self.message.clone()
    }
    
    pub fn revieve_message(&mut self, message: Message) -> Result<(), Box<dyn Error>> {
        self.retched_recv()?;
        self.add_message(message);
        Ok(())
    }
    
    pub fn add_message(&self, message: Message) {
        let mut messages = self.message.lock().unwrap();
        messages.push(message);
    }
    
    fn retched_send(&mut self) -> Result<(), Box<dyn Error>> {
        let prk = Salt::new(HKDF_SHA256, &self.send_chain_key).extract(&[]);
        
        let mut message_key = [0u8; 32];
        prk.expand(&[b"message key"], HKDF_SHA256).unwrap()
            .fill(&mut message_key)
            .unwrap();
        
        self.send_chain_key = message_key;
        Ok(())
    }
    
    fn retched_recv(&mut self) -> Result<(), Box<dyn Error>> {
        let prk = Salt::new(HKDF_SHA256, &self.recv_chain_key).extract(&[]);
        
        let mut message_key = [0u8; 32];
        prk.expand(&[b"message key"], HKDF_SHA256).unwrap()
            .fill(&mut message_key)
            .unwrap();
        
        self.recv_chain_key = message_key;
        Ok(())
    }
}


fn verify_spk_signature(ikp_public: &[u8], spk: &[u8], spk_sig: &[u8]) -> Result<(), Box<dyn Error>> {
    let public_key = UnparsedPublicKey::new(&ED25519, ikp_public);
    public_key.verify(spk, spk_sig).map_err(|e| format!("Failed to verify signature: {}", e))?;
    info!("Verified signature");
    Ok(())
}

fn x3dh(ikp: [u8; 32], spk: [u8; 32], opk: [u8; 32], ik: [u8; 32], ek: [u8; 32]) -> Result<[u8; 32], Box<dyn Error>> {
    let dh1 = x25519(ik, spk);
    let dh2 = x25519(ek, ikp);
    let dh3 = x25519(ek, spk);
    let dh4 = x25519(ek, opk);

    let mut key_material = Vec::new();
    key_material.extend_from_slice(&dh1);
    key_material.extend_from_slice(&dh2);
    key_material.extend_from_slice(&dh3);
    key_material.extend_from_slice(&dh4);

    let hk = Hkdf::<Sha256>::new(None, &key_material);
    let mut session_key = [0u8; 32];
    hk.expand(b"X3DH-Session-Key", &mut session_key).map_err(|e| format!("Failed to expand key: {}", e))?;

    Ok(session_key)
}

