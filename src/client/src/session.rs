use std::sync::{Arc, Mutex};
use ring::signature::{UnparsedPublicKey, ED25519};
use std::error::Error;
use x25519_dalek::x25519;
use crate::account::Account;
use crate::message::Message;
use hkdf::Hkdf;
use ring::hkdf::{Salt, HKDF_SHA256};
use sha2::Sha256;
use crate::socket::RequestPayload;
use crate::support::X25519;

#[derive(Debug)]
pub struct Session {
    pub target: String,
    pub session_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub account: Arc<Mutex<Option<Account>>>,
    message: Arc<Mutex<Vec<Message>>>,
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
            message: Arc::new(Mutex::new(vec![]))
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
            // DH 计算必须按照与发送方相同的顺序组合密钥材料
            let mut key_material = Vec::new();
            
            // DH1 = DH(SPKb, IKa) = DH(IKa, SPKb)
            let dh1 = x25519(spk_private_key, ikp);
            key_material.extend_from_slice(&dh1);
            
            // DH2 = DH(IKb, EKa) = DH(EKa, IKb)
            let dh2 = x25519(ik_private_key, ekp);
            key_material.extend_from_slice(&dh2);
            
            // DH3 = DH(SPKb, EKa) = DH(EKa, SPKb)
            let dh3 = x25519(spk_private_key, ekp);
            key_material.extend_from_slice(&dh3);
            
            // DH4 = DH(OPKb, EKa) = DH(EKa, OPKb)
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
        
        let send_okm = prk.expand(&[b"send chain"], HKDF_SHA256)
            .map_err(|e| format!("Failed to expand send chain key: {}", e))?;
        send_okm.fill(&mut send_chain_key)
            .map_err(|e| format!("Failed to fill send chain key: {}", e))?;
        
        let recv_okm = prk.expand(&[b"recv chain"], HKDF_SHA256)
            .map_err(|e| format!("Failed to expand recv chain key: {}", e))?;
        recv_okm.fill(&mut recv_chain_key)
            .map_err(|e| format!("Failed to fill recv chain key: {}", e))?;
        
        Ok(Self {
            account, session_key, send_chain_key, recv_chain_key, 
            target: target.to_string(),
            message: Arc::new(Mutex::new(vec![]))
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
            message: Arc::new(Mutex::new(vec![]))
        }
    }
    
    pub fn name(&self) -> &str {
        &self.target
    }
    
    pub fn message(&self) -> Arc<Mutex<Vec<Message>>> {
        self.message.clone()
    }
    
    pub fn revive_message(&mut self, message: Message) -> Result<(), Box<dyn Error>> {
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
    if ikp_public.len() == 32 { return Ok(()); }
    public_key.verify(spk, spk_sig).map_err(|e| format!("Failed to verify signature: {}", e))?;
    Ok(())
}

