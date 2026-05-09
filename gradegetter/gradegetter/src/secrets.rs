use std::sync::LazyLock;

pub struct Secrets {
    pub database_url: String,
    #[allow(dead_code)]
    // its not defined or used anywhere but needed bc crypto_utils
    // needs ts env var
    pub encryption_key: String,
    pub internal_api_key: String,
}

pub static SECRETS: LazyLock<Secrets> = LazyLock::new(|| {
    dotenvy::dotenv().ok();
    Secrets {
        database_url: dotenvy::var("DATABASE_URL").expect("DATABASE_URL env var not found"),
        // again not used anywhere but look at line 6 and 7 mMUHAMHAHHAHAH
        encryption_key: dotenvy::var("ENCRYPTION_KEY").expect("ENCRYPTION_KEY env var not found"),
        internal_api_key: dotenvy::var("INTERNAL_API_KEY")
            .expect("INTERNAL_API_KEY env var missing"),
    }
});
