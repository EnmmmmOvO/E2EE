let message_key = self.ratchet_send(new_dh.public)?;

let key = Key::<Aes256Gcm>::from_slice(&message_key);
let cipher = Aes256Gcm::new(key);
let mut nonce_bytes = [0u8; 12];
OsRng.fill_bytes(&mut nonce_bytes);
let nonce = Nonce::from_slice(&nonce_bytes);

let ciphertext = cipher.encrypt(nonce, message.text.as_bytes())
    .map_err(|e| format!("Failed to encrypt message: {}", e))?;

let payload = hex::encode(header_bytes) + &hex::encode(nonce_bytes) + &hex::encode(ciphertext);