use std::error::Error;

pub fn v32(vec: Vec<u8>) -> Result<[u8; 32], Box<dyn Error>> {
    let array: [u8; 32] = vec.try_into().map_err(|_| "Expected a Vec of length 32")?;
    Ok(array)
}

pub fn string_to_v32(s: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let vec = hex::decode(s)?;
    v32(vec)
}