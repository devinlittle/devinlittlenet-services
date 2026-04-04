use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::{headers::Cookie, TypedHeader};
use hyper::{header::SET_COOKIE, HeaderMap};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{types::uuid, FromRow, PgPool};
use time::{OffsetDateTime, PrimitiveDateTime};
use tracing::{error, info};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    middleware::jwt::{AuthenticatedUser, Claims},
    util::{
        hash::{hash, validate},
        random::generate_random_string,
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
    path = "/auth/register",
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
    let password_hash: String = hash(&req.password);
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
        (status = 200, description = "Returns Valid JWT for User", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn login_handler(
    State(pool): State<PgPool>,
    Json(req): Json<LoginInput>,
) -> Result<impl IntoResponse, StatusCode> {
    let row = sqlx::query_as!(
        ReturnDB,
        "SELECT id, password_hash, username, roles FROM users WHERE username = $1",
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

    if validate(req.password.as_str(), &user.password_hash) {
        let sub = user.id.to_string();
        let username = req.username.to_string();
        let iat = OffsetDateTime::now_utc();
        let exp = iat + time::Duration::days(365);

        let access_token = generate_jwt(sub, username, user.roles, iat, exp)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let refresh_token = generate_random_string();

        let refresh_cookie = format!(
            "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Path=/auth/refresh; Max-Age={}",
            refresh_token,
            60 * 60 * 24 * 365 // this is a year - Devin Little
        );
        insert_refresh_token(pool, user.id, &refresh_token)
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
}

#[utoipa::path(
    delete,
    path = "/auth/delete",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Deleted User", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 404, description = "Not Found"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn delete_handler(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    match sqlx::query!("DELETE FROM users WHERE id = $1", user.uuid)
        .execute(&pool)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            info!("deleted user: {}", user.username);
            axum::http::StatusCode::OK
        }
        Ok(_) => StatusCode::NOT_FOUND,
        Err(err) => {
            error!("database error: {:?}", err);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
    }
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

pub async fn refresh_handler(
    State(pool): State<PgPool>,
    TypedHeader(cookies): TypedHeader<Cookie>,
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
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let uuid = match refresh_token_query {
        Some(re) => re.user_id,
        None => return Err(StatusCode::UNAUTHORIZED), // token invalid or already used
    };

    let user = sqlx::query!(
        "SELECT id, password_hash, username, roles FROM users WHERE id = $1",
        uuid
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let sub = user.id.to_string();
    let username = user.username;
    let iat = OffsetDateTime::now_utc();
    let exp = iat + time::Duration::days(365);

    let access_token = generate_jwt(sub, username, user.roles, iat, exp)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let refresh_cookie = format!(
        "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Path=/auth/refresh; Max-Age={}",
        refresh_token,
        60 * 60 * 24 * 365 // this is a year - Devin Little
    );

    insert_refresh_token(pool.clone(), uuid, &refresh_token)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut headers = HeaderMap::new();

    headers.insert(SET_COOKIE, HeaderValue::from_str(&refresh_cookie).unwrap());

    Ok((headers, Json(LoginOutput { access_token })).into_response())
}

pub fn generate_jwt(
    sub: String,
    username: String,
    roles: Value,
    iat: OffsetDateTime,
    exp: OffsetDateTime,
) -> Result<String, StatusCode> {
    let jwt_secret = dotenvy::var("JWT_SECRET").unwrap();

    let claims = Claims {
        sub,
        username,
        roles,
        iat,
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(token)
}

#[allow(clippy::ptr_arg)]
pub async fn insert_refresh_token(
    pool: PgPool,
    uuid: Uuid,
    refresh_token: &String,
) -> Result<(), StatusCode> {
    let expires_at = PrimitiveDateTime::new(
        OffsetDateTime::now_utc().date(),
        OffsetDateTime::now_utc().time(),
    ) + time::Duration::days(365);
    let _ = sqlx::query!(
        r#"INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)"#,
        uuid,
        hash(refresh_token.as_str()),
        expires_at
    )
    .execute(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}
