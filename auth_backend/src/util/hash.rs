use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use constant_time_eq::constant_time_eq;
use hyper::StatusCode;
use sha2::{Digest, Sha256};
use tracing::instrument;

use crate::util::secrets::SECRETS;

#[instrument(
    name = "crypto.hash_password",
    skip(password),
    fields(crypto.algorithm = "argon2id")
)]
pub fn hash_password(password: String) -> Result<String, StatusCode> {
    let salt = &SECRETS.hash_secret;
    let salt = SaltString::encode_b64(salt.as_bytes()).expect("SaltString initilization");

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| {
            tracing::error!(error = %err, "Cryptographic failure processing password hash");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_string();
    Ok(password_hash)
}

#[allow(clippy::needless_return)]
#[instrument(
    name = "crypto.verify_password",
    skip(original, hashed_password),
    fields(crypto.algorithm = "argon2id")
)]
pub fn verify_password(original: &str, hashed_password: &str) -> bool {
    let argon2 = Argon2::default();

    let parsed = PasswordHash::new(hashed_password)
        .map_err(|err| {
            tracing::error!(error = %err, "Database contained an invalid or corrupted password hash format");
        })
        .unwrap();

    return argon2.verify_password(original.as_bytes(), &parsed).is_ok();
}

#[instrument(
    name = "crypto.hash",
    skip(data),
    fields(crypto.algorithm = "sha256")
)]
pub fn hash(data: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let salt = &SECRETS.hash_secret;
    hasher.update(salt);
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[instrument(name = "crypto.validate", skip(original, hashed))]
pub fn validate(original: &str, hashed: Vec<u8>) -> bool {
    let original_hashed = hash(original);
    constant_time_eq(&original_hashed, &hashed)
}
