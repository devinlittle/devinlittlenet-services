use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::{
    headers::{Cookie, UserAgent},
    TypedHeader,
};
use hyper::{header::SET_COOKIE, HeaderMap};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sqlx::{types::uuid, FromRow, PgPool};
use time::{OffsetDateTime, PrimitiveDateTime};
use tracing::{error, info};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    middleware::jwt::{jwt_numeric_date, AuthenticatedUser, Claims},
    util::{
        hash::{hash, hash_password, verify_password},
        random::generate_random_string,
        secrets::SECRETS,
    },
};

#[derive(Deserialize, ToSchema)]
pub struct RegisterInput {
    #[schema(example = "user")]
    username: String,
    #[schema(example = "password")]
    password: String,
}

#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterInput,
    responses(
        (status = 200, description = "Registers User!", body = String),
        (status = 409, description = "User exists")
    ),
    tag = "user_auth"
)]
pub async fn register_handler(
    State(pool): State<PgPool>,
    Json(req): Json<RegisterInput>,
) -> Result<Json<String>, axum::http::StatusCode> {
    let password_hash: String = hash_password(req.password)?;
    sqlx::query("INSERT INTO users (username, password_hash) VALUES ($1, $2)")
        .bind(&req.username)
        .bind(&password_hash)
        .execute(&pool)
        .await
        .map_err(|_| axum::http::StatusCode::CONFLICT)?;
    info!("User {:?} Registered", &req.username);
    Ok(Json("User registered".to_string()))
}

#[derive(Deserialize, ToSchema)]
pub struct LoginInput {
    #[schema(example = "user")]
    username: String,
    #[schema(example = "password")]
    password: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct ReturnDB {
    id: uuid::Uuid,
    username: String,
    roles: serde_json::Value,
    password_hash: String,
    public_key: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct LoginOutput {
    access_token: String,
}

#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginInput,
    responses(
        (status = 200, description = "Returns Valid JWT for User and SET_COOKIE header for refreshing purposes", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn login_handler(
    State(pool): State<PgPool>,
    TypedHeader(user_agent): TypedHeader<UserAgent>,
    Json(req): Json<LoginInput>,
) -> Result<impl IntoResponse, StatusCode> {
    let row = sqlx::query_as!(
        ReturnDB,
        "SELECT id, password_hash, username, roles, public_key FROM users WHERE username = $1",
        &req.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|err| {
        tracing::info!("Database error: {}", err);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user = match row {
        Some(user) => user,
        None => return Err(axum::http::StatusCode::UNAUTHORIZED), // User not found
    };

    if verify_password(req.password.as_str(), &user.password_hash) {
        let sub = user.id.to_string();
        let username = req.username.to_string();
        let iat = OffsetDateTime::now_utc();
        let exp = iat + time::Duration::minutes(15);

        let access_token = generate_jwt(Claims {
            sub,
            username,
            roles: user.roles,
            public_key: user.public_key,
            iat,
            exp,
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let refresh_token = generate_random_string();

        let refresh_cookie = format!(
            "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
            refresh_token,
            60 * 60 * 24 * 365 // this is a year - Devin Little
        );
        insert_refresh_token(pool, user.id, &refresh_token, user_agent.to_string())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut headers = HeaderMap::new();

        headers.insert(SET_COOKIE, HeaderValue::from_str(&refresh_cookie).unwrap());

        info!(r#"User "{}" logged in sucessfully"#, user.username);
        Ok((headers, Json(LoginOutput { access_token }).into_response()))
    } else {
        info!(
            r#"User failed to login; username: "{0}", id: "{1}""#,
            user.username, user.id
        );
        Err(axum::http::StatusCode::UNAUTHORIZED)
    }
}

#[utoipa::path(
    post,
    path = "/logout",
    security(
        ("cookie_auth" = [])
    ),
    responses(
        (status = 200, description = "Sends back an empty, expired cookie to client ", body = String),
        (status = 401, description = "the refresh_token cookie the user send is messed tf up"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn logout_handler(
    State(pool): State<PgPool>,
    TypedHeader(cookies): TypedHeader<Cookie>,
) -> Result<impl IntoResponse, StatusCode> {
    let refresh_cookie = cookies.get("refresh_token").unwrap_or_default();

    let query = format!(
        "DELETE FROM refresh_tokens WHERE token_hash = '{}'",
        hash(refresh_cookie)
    );

    tracing::debug!("{query}");

    if sqlx::query(&query)
        .execute(&pool)
        .await
        .map_err(|err| {
            tracing::error!("{}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })
        .is_ok()
    {
        let refresh_cookie = "refresh_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";

        let mut headers = HeaderMap::new();

        headers.insert(SET_COOKIE, HeaderValue::from_str(refresh_cookie).unwrap());

        info!(r#"User logged out sucessfully"#);
        Ok((StatusCode::OK, headers).into_response())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/*#[utoipa::path(
    get,
    path = "/auth/validate",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User token is valid", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn validate_token() -> Result<(), StatusCode> {
    Ok(())
} */

#[utoipa::path(
    post,
    path = "/refresh",
    security(
        ("cookie_auth" = [])
    ),
    responses(
        (status = 200, description = "sent back jwt and refresh_cookie", body = String),
        (status = 401, description = "cookie messed tf up"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn refresh_handler(
    State(pool): State<PgPool>,
    TypedHeader(cookies): TypedHeader<Cookie>,
    TypedHeader(user_agent): TypedHeader<UserAgent>,
) -> Result<impl IntoResponse, StatusCode> {
    let cookie_refresh_token = cookies.get("refresh_token").unwrap_or_default();

    let valid_token = sqlx::query!(
        "SELECT token_hash FROM refresh_tokens WHERE token_hash = $1",
        hash(cookie_refresh_token)
    )
    .fetch_optional(&pool)
    .await
    .map_err(|err| {
        tracing::error!("{}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .is_some();

    if !valid_token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let refresh_token = generate_random_string();

    let refresh_token_query = sqlx::query!(
        "UPDATE refresh_tokens
         SET revoked_at = NOW(), replaced_by_token = $2
         WHERE token_hash = $1
         AND revoked_at IS NULL
         AND expires_at > NOW()
         RETURNING user_id",
        hash(cookie_refresh_token),
        hash(refresh_token.as_str())
    )
    .fetch_optional(&pool)
    .await
    .map_err(|err| {
        tracing::error!("error updating refresh_tokens: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let uuid = match refresh_token_query {
        Some(re) => re.user_id,
        None => return Err(StatusCode::UNAUTHORIZED), // token invalid or already used
    };

    let user = sqlx::query!(
        "SELECT id, password_hash, username, roles, public_key FROM users WHERE id = $1",
        uuid
    )
    .fetch_one(&pool)
    .await
    .map_err(|err| {
        tracing::error!("error grabbing user information from db: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let sub = user.id.to_string();
    let username = user.username.clone();
    let iat = OffsetDateTime::now_utc();
    let exp = iat + time::Duration::minutes(15);

    let access_token = generate_jwt(Claims {
        sub,
        username,
        roles: user.roles,
        public_key: user.public_key,
        iat,
        exp,
    })
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let refresh_cookie = format!(
        "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        refresh_token,
        60 * 60 * 24 * 365 // this is a year - Devin Little
    );

    insert_refresh_token(pool.clone(), uuid, &refresh_token, user_agent.to_string())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = HeaderMap::new();

    headers.insert(SET_COOKIE, HeaderValue::from_str(&refresh_cookie).unwrap());

    tracing::debug!("Refreshed ref_token for user: {}", user.username);
    Ok((headers, Json(LoginOutput { access_token })).into_response())
}

pub fn generate_jwt(claims: Claims) -> Result<String, StatusCode> {
    let jwt_secret = &SECRETS.jwt_secret;

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|err| {
        tracing::error!("error encoding jwt, {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(token)
}

#[allow(clippy::ptr_arg)]
pub async fn insert_refresh_token(
    pool: PgPool,
    uuid: Uuid,
    refresh_token: &String,
    user_agent: String,
) -> Result<(), StatusCode> {
    let expires_at = PrimitiveDateTime::new(
        OffsetDateTime::now_utc().date(),
        OffsetDateTime::now_utc().time(),
    ) + time::Duration::days(365);
    let _ = sqlx::query!(
        r#"INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent) VALUES ($1, $2, $3, $4)"#,
        uuid,
        hash(refresh_token.as_str()),
        expires_at,
        user_agent
    )
    .execute(&pool)
    .await
    .map_err(|err| {
        tracing::error!("erorr adding refreh_token to db {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(())
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is alive"),
    ),
    tag = "none"
)]
pub async fn health() -> Result<(), axum::http::StatusCode> {
    Ok(())
}
