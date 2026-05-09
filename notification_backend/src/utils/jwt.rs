use std::sync::Arc;

use crate::{routes::AppState, utils::secrets::SECRETS};
use axum::{extract::State, http::StatusCode};
use common::{AuthenticatedUser, Claims};
use jsonwebtoken::{DecodingKey, Validation};

pub async fn jwt_parse(
    State(state): State<AppState>,
    token: &str,
) -> Result<AuthenticatedUser, StatusCode> {
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    let decoding_key = DecodingKey::from_secret(SECRETS.jwt_secret.as_bytes());

    let decoded_jwt = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation)
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
        .get(&common::ServiceName::Notifications)
        .or_else(|| decoded_jwt.roles.get(&common::ServiceName::Global))
        .unwrap_or(&common::UserRole::User)
        .clone();

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

    Ok(AuthenticatedUser {
        username,
        uuid,
        role,
    })
}
