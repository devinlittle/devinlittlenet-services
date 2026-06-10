use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use dotenvy::dotenv;
use rand::{rng, Rng};
use std::{env, sync::LazyLock};
use thiserror::Error;
use tracing::{error, instrument};

static ENCRYPTION_KEY: LazyLock<Key<Aes256Gcm>> = LazyLock::new(|| {
    dotenv().ok();
    let key_b64 = env::var("ENCRYPTION_KEY").expect("ENCRYPTION_KEY not set");
    let key_bytes = general_purpose::STANDARD
        .decode(&key_b64)
        .expect("Invalid Base64 encryption key");
    if key_bytes.len() != 32 {
        panic!("ENCRYPTION_KEY must be 32 bytes (Base64-encoded)");
    }
    Key::<Aes256Gcm>::from_slice(&key_bytes).to_owned()
});

#[derive(Error, Debug)]
pub enum CryptoErrors {
    #[error("failed to encrypt data")]
    EncryptionError,
    #[error("failed to decrypt data")]
    DecryptionError,
    #[error("failed to encode data to utf8")]
    EncodingError,
    #[error("data is less than 12 bytes")]
    TooLittleData,
}

#[instrument(
    name = "crypto.encrypt",
    skip(plaintext),
    fields(
        crypto.algorithm = "aes-256-gcm",
        crypto.operation = "encrypt",
        payload.size_bytes = plaintext.len()
    )
)]
pub fn encrypt_string(plaintext: &str) -> Result<Vec<u8>, CryptoErrors> {
    let cipher = Aes256Gcm::new(&ENCRYPTION_KEY);

    let mut nonce_bytes = [0u8; 12];
    rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).map_err(|err| {
        error!(error = %err, "[Crypto_Utils failure]: failure to encrypt data");
        CryptoErrors::EncryptionError
    })?;

    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);

    Ok(combined)
}

// TODO: add special error types for this
#[instrument(
    name = "crypto.decrypt",
    skip(data),
    fields(
        crypto.algorithm = "aes-256-gcm",
        crypto.operation = "decrypt",
        payload.size_bytes = data.len()
    )
)]
pub fn decrypt_string(data: Vec<u8>) -> Result<String, CryptoErrors> {
    if data.len() < 12 {
        error!("[Crypto_Utils failure]: too little data to decrypt");
        return Err(CryptoErrors::TooLittleData);
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(&ENCRYPTION_KEY);

    let decrypted_bytes = cipher.decrypt(nonce, ciphertext).map_err(|err| {
        error!(error = %err, "[Crypto_Utils failure]: failure to decyrpt data");
        CryptoErrors::TooLittleData
    })?;

    String::from_utf8(decrypted_bytes).map_err(|err| {
        error!(error = %err, "[Crypto_Utils failure]: failed to encode decrypted data into utf8");
        CryptoErrors::EncodingError
    })
}
