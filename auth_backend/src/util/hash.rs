use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use constant_time_eq::constant_time_eq;
use hyper::StatusCode;
use sha2::{Digest, Sha256};

pub fn hash_password(password: String) -> Result<String, StatusCode> {
    let salt = dotenvy::var("HASH_SECRET").expect("HASH_SECRET must be set in .env file");
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

pub fn verify_password(original: &str, hashed_password: &str) -> bool {
    let argon2 = Argon2::default();

    let parsed = PasswordHash::new(hashed_password).unwrap();

    return argon2.verify_password(original.as_bytes(), &parsed).is_ok();
}

pub fn hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    let salt = dotenvy::var("HASH_SECRET").expect("HASH_SECRET must be set in .env file");
    hasher.update(salt);
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[allow(dead_code)]
pub fn validate(original: &str, hashed: &str) -> bool {
    let original_hashed = hash(original);
    constant_time_eq(original_hashed.as_bytes(), hashed.as_bytes())
}
