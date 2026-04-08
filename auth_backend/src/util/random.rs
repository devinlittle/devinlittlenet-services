use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rng, Rng};

pub fn generate_random_string() -> String {
    let mut bytes = [0u8; 128];
    rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
