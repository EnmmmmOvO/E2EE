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