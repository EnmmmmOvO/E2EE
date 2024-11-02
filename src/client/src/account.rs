use std::error::Error;
use crate::key::{AccountKeys, IdentityKeyPair, SignedPreKeyPair};

#[derive(Clone, Debug)]
pub struct Account {
    account: String,
    key: AccountKeys,
}

impl Account {
    pub async fn new(account: String) -> Result<Self, Box<dyn Error>> {
        let key = AccountKeys::new(&account).await?;
        Ok(Self { account, key })
    }
    
    pub fn load(account: String) -> Result<Self, Box<dyn Error>> {
        let key = AccountKeys::load(&account)?;
        Ok(Self { account, key })
    }
    
    pub fn name(&self) -> &str {
        &self.account
    }
    
    pub fn ik(&self) -> &IdentityKeyPair {
        &self.key.identity_keypair
    }
    
    pub fn spk(&self) -> &SignedPreKeyPair {
        &self.key.signed_prekey
    }
    
    pub fn find_opk(&self, id: i32) -> Option<[u8; 32]> {
        self.key.one_time_prekeys.iter()
            .find(|k| k.id == id)
            .map(|k| k.key)
    }
}