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