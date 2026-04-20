use std::sync::LazyLock;

pub struct Secrets {
    pub jwt_secret: String,
    pub internal_api_key: String,
}

pub static SECRETS: LazyLock<Secrets> = LazyLock::new(|| {
    dotenvy::dotenv().ok();
    Secrets {
        jwt_secret: dotenvy::var("JWT_SECRET").expect("JWT_SECRET env var not found"),
        internal_api_key: dotenvy::var("INTERNAL_API_KEY")
            .expect("INTERNAL_API_KEY env var missing"),
    }
});
