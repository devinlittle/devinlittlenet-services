use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::{routes::AppState, utils::secrets::SECRETS};

#[derive(Clone, ToSchema)]
#[allow(dead_code)]
pub struct AuthenticatedUser {
    pub username: String,
    pub uuid: uuid::Uuid,
    pub role: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, ToSchema)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub roles: serde_json::Value,
    #[serde(with = "jwt_numeric_date")]
    pub iat: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    pub exp: OffsetDateTime,
}

pub async fn jwt_auth(
    State(state): State<AppState>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let decoding_key = DecodingKey::from_secret(SECRETS.jwt_secret.as_bytes());

    let decoded_jwt = jsonwebtoken::decode::<Claims>(bearer.token(), &decoding_key, &validation)
        .map(|x| x.claims)
        .map_err(|err| {
            match *err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    tracing::warn!("InvalidToken");
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    tracing::warn!("InvalidSignature");
                }
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    tracing::warn!("ExpiredSignature");
                }
                _ => {
                    tracing::warn!("Token verification failed: {:?}", err);
                }
            }
            StatusCode::UNAUTHORIZED
        })?;

    let uuid = uuid::Uuid::parse_str(&decoded_jwt.sub).map_err(|_| StatusCode::BAD_REQUEST)?;
    let username = decoded_jwt.username;
    let role = decoded_jwt
        .roles
        .get("global")
        .and_then(|v| v.as_str())
        .unwrap_or("user")
        .to_string();

    let seen_users = Arc::clone(&state.seen_users);

    let is_seen = {
        let read = seen_users
            .read()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        read.contains(&uuid)
    };

    if !is_seen {
        // insert new uuid to db if not in already
        if sqlx::query!("SELECT id FROM service_users WHERE id = $1", uuid)
            .fetch_optional(&state.pool)
            .await
            .map_err(|err| {
                tracing::error!("{}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })?
            .is_none()
        {
            sqlx::query!(
                "INSERT INTO service_users (id, username) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                uuid,
                username
            )
            .execute(&state.pool)
            .await
            .map_err(|err| {
                tracing::error!("{}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        }

        let mut write = seen_users
            .write()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        write.insert(uuid);
    }

    request.extensions_mut().insert(AuthenticatedUser {
        username,
        uuid,
        role,
    });

    Ok(next.run(request).await)
}

pub mod jwt_numeric_date {
    //! Custom serialization of OffsetDateTime to conform with the JWT spec (RFC 7519 section 2, "Numeric Date")
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    /// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = date.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }

    /// Attempts to deserialize an i64 and use as a Unix timestamp
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}
