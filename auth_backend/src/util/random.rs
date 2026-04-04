use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;

pub fn generate_random_string() -> String {
    let mut bytes = [0u8; 128];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
