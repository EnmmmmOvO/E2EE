let mut private = [0u8; 32];
OsRng.fill_bytes(&mut private);

let secret = StaticSecret::from(private);
let public_key = PublicKey::from(&secret);