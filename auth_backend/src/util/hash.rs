use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use constant_time_eq::constant_time_eq;
use hyper::StatusCode;
use sha2::{Digest, Sha256};

use crate::util::secrets::SECRETS;

pub fn hash_password(password: String) -> Result<String, StatusCode> {
    let salt = &SECRETS.hash_secret;
    let salt = SaltString::encode_b64(salt.as_bytes()).expect("SaltString initilization");

    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| {
            tracing::error!("error hashing password: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_string();
    Ok(password_hash)
}

#[allow(clippy::needless_return)]
pub fn verify_password(original: &str, hashed_password: &str) -> bool {
    let argon2 = Argon2::default();

    let parsed = PasswordHash::new(hashed_password)
        .map_err(|err| {
            tracing::error!("error verifying password: {}", err);
        })
        .unwrap();

    return argon2.verify_password(original.as_bytes(), &parsed).is_ok();
}

pub fn hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    let salt = &SECRETS.hash_secret;
    hasher.update(salt);
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

//  XXX: depricated, used by old login auth; still might have uses later...
#[allow(dead_code)]
pub fn validate(original: &str, hashed: &str) -> bool {
    let original_hashed = hash(original);
    constant_time_eq(original_hashed.as_bytes(), hashed.as_bytes())
}
