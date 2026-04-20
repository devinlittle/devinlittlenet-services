use std::sync::LazyLock;

pub struct Secrets {
    pub database_url: String,
    pub hash_secret: String,
    pub jwt_secret: String,
    pub internal_api_key: String,
}

pub static SECRETS: LazyLock<Secrets> = LazyLock::new(|| {
    dotenvy::dotenv().ok();
    Secrets {
        database_url: dotenvy::var("DATABASE_URL").expect("DATABASE_URL env var not found"),
        hash_secret: dotenvy::var("HASH_SECRET").expect("HASH_SECRET must be set in .env file"),
        jwt_secret: dotenvy::var("JWT_SECRET").expect("JWT_SECRET env var not found"),
        internal_api_key: dotenvy::var("INTERNAL_API_KEY")
            .expect("INTERNAL_API_KEY env var missing"),
    }
});
