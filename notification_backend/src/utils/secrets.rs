use std::sync::LazyLock;

use web_push::{PartialVapidSignatureBuilder, VapidSignatureBuilder};

pub struct Secrets {
    pub database_url: String,
    pub jwt_secret: String,
    pub internal_api_key: String,
    pub vapid_private_key: PartialVapidSignatureBuilder,
    pub vapid_public_key: String,
}

pub static SECRETS: LazyLock<Secrets> = LazyLock::new(|| {
    dotenvy::dotenv().ok();
    Secrets {
        database_url: dotenvy::var("DATABASE_URL").expect("MISSING DA DATABASE_URL ENV VAR"),
        jwt_secret: dotenvy::var("JWT_SECRET").expect("JWT_SECRET env var not found"),
        internal_api_key: dotenvy::var("INTERNAL_API_KEY")
            .expect("INTERNAL_API_KEY env var missing"),
        vapid_private_key: VapidSignatureBuilder::from_base64_no_sub(
            dotenvy::var("VAPID_PRIVATE_KEY")
                .expect("missing vapid private key :(")
                .as_str(),
        )
        .expect("MISSING DA VAPID PRIVATE KEY ENV VAR"),
        vapid_public_key: dotenvy::var("VAPID_PUBLIC_KEY")
            .expect("MISSING DA VAPID PUBLIC KEYENV VAR"),
    }
});
