use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_extra::{
    headers::{Cookie, UserAgent},
    TypedHeader,
};
use chrono::{DateTime, Duration, Utc};
use hyper::{header::SET_COOKIE, HeaderMap};
use jsonwebtoken::{encode, EncodingKey, Header};
use sqlx::{types::uuid, PgPool};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use common::{
    auth::{LoginInput, LoginOutput, RegisterInput},
    Claims,
};

use crate::util::{
    hash::{hash, hash_password, verify_password},
    random::generate_random_string,
    secrets::SECRETS,
};

#[instrument(
    name = "user_registration",
    skip(pool, req),
    fields(
        user.username = %req.username,
        security.event = "authentication"
    )
)]
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
    let user_row = sqlx::query!(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
        req.username,
        password_hash,
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| axum::http::StatusCode::CONFLICT)?;

    info!(
        target: "audit",
        action = "auth.register",
        user.id = %user_row.id,
        user.username = %req.username,
        "[Security Event]: New user account registered"
    );

    Ok(Json("User registered".to_string()))
}

#[derive(sqlx::FromRow)]
struct UserRow {
    pub id: uuid::Uuid,
    pub username: String,
    pub password_hash: String,
    pub roles: serde_json::Value,
    pub public_key: Option<String>,
}

impl UserRow {
    pub fn try_into_roles(&self) -> Result<common::UserRoles, StatusCode> {
        serde_json::from_value(self.roles.clone()).map_err(|e| {
            error!("Role mapping failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
    }
}

#[instrument(
    name = "user_login",
    skip(pool, req),
    fields(
        user.username = %req.username,
        security.event = "authentication"
    )
)]
#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginInput,
    responses(
        (status = 200, description = "Returns Valid JWT for User and SET_COOKIE header for refreshing purposes", body = LoginOutput),
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
        UserRow,
        "SELECT id, password_hash, username, roles, public_key FROM users WHERE username = $1",
        &req.username
    )
    .fetch_optional(&pool)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: failed to look up user during login");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user = match row {
        Some(user) => {
            tracing::Span::current().record("user.id", tracing::field::display(user.id));
            user
        }
        None => {
            warn!(
                target: "audit",
                action = "auth.login",
                reason = "username_not_found",
                user.username = %req.username,
                "[Security Alert]: Failed login attempt on non existent username"
            );
            return Err(axum::http::StatusCode::UNAUTHORIZED);
        } // User not found
    };

    if verify_password(req.password.as_str(), &user.password_hash) {
        let sub = user.id;
        let username = req.username.to_string();
        let iat: DateTime<Utc> = Utc::now();
        let exp = iat + Duration::minutes(15);

        let access_token = generate_jwt(Claims {
            sub,
            username,
            roles: user.try_into_roles().map_err(|e| {
                error!(error = %e, "[Database failure]: Failed to serialize user roles into JWT claims");
                StatusCode::INTERNAL_SERVER_ERROR
            })?,
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
            .map_err(|err| {
                error!(error = %err, "Failed to write active refresh token to db");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let mut headers = HeaderMap::new();

        headers.insert(SET_COOKIE, HeaderValue::from_str(&refresh_cookie).unwrap());

        info!(
            target: "audit",
            action = "auth.login",
            user.id = %user.id,
            user.username = %user.username,
            device.user_agent = %user_agent,
            "[Security Event]: User logged in successfully"
        );

        Ok((headers, Json(LoginOutput { access_token }).into_response()))
    } else {
        warn!(
            target: "audit",
            action = "auth.login",
            reason = "invalid_credentials",
            user.id = %user.id,
            user.username = %user.username,
            device.user_agent = %user_agent,
            "[Security Alert]: Failed login attempt with incorrect credentials"
        );

        Err(axum::http::StatusCode::UNAUTHORIZED)
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

#[instrument(
    name = "user_refresh",
    skip(pool, cookies, user_agent),
    fields(
        security.event = "authentication"
    )
)]
#[utoipa::path(
    post,
    path = "/refresh",
    security(
        ("cookie_auth" = [])
    ),
    responses(
        (status = 200, description = "sent back jwt and refresh_cookie", body = LoginOutput),
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
    if cookies.get("refresh_token").is_some_and(|x| x.is_empty())
        || cookies.get("refresh_token").is_none()
    {
        warn!(
            target: "audit",
            action = "auth.refresh",
            reason = "no refresh_token provided",
            "[Security Alert]: Failed refresh a token; no token"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    let cookie_refresh_token = cookies.get("refresh_token").unwrap_or_default();

    let old_token_query = sqlx::query!(
        "SELECT user_id, token_hash FROM refresh_tokens WHERE token_hash = $1",
        hash(cookie_refresh_token)
    )
    .fetch_optional(&pool)
    .await
    .map_err(|err| {
        error!(error = %err, "Failed to get user_id and token_hash from refresh tokens");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let (valid_token, user_id) = match old_token_query {
        Some(token) => (true, token.user_id),
        None => {
            warn!(
                target: "audit",
                action = "auth.refresh",
                reason = "token_not_found",
                device.user_agent = %user_agent,
                "[Security Alert]: Failed refresh token that does not exist"
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    if !valid_token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let refresh_token = generate_random_string();

    let new_refresh_id = insert_refresh_token(
        pool.clone(),
        user_id,
        &refresh_token,
        user_agent.to_string(),
    )
    .await
    .map_err(|err| {
        error!(error = %err, "Failed to insert new refersh_token");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query!(
        "UPDATE refresh_tokens
         SET revoked_at = NOW(), replaced_by_token = $2
         WHERE token_hash = $1
         AND revoked_at IS NULL
         AND expires_at > NOW()",
        hash(cookie_refresh_token),
        new_refresh_id,
    )
    .fetch_optional(&pool)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: Failed to set old token as revoked");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let user = sqlx::query_as!(
        UserRow,
        "SELECT id, password_hash, username, roles, public_key FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: Failed to grab user info during token refresh");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let sub = user.id;
    let username = user.username.clone();
    let iat: DateTime<Utc> = Utc::now();
    let exp = iat + Duration::minutes(15);

    let access_token = generate_jwt(Claims {
        sub,
        username,
        roles: user.try_into_roles()?,
        public_key: user.public_key,
        iat,
        exp,
    })
    .map_err(|err| {
        error!(error = %err, "failed to generate jwt");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let refresh_cookie = format!(
        "refresh_token={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        refresh_token,
        60 * 60 * 24 * 365 // this is a year - Devin Little
    );

    let mut headers = HeaderMap::new();

    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&refresh_cookie).map_err(|err| {
            error!(error = %err, "failed to adttach new refresh token to headers");
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
    );

    info!(
        target: "audit",
        action = "auth.refresh",
        user.id = %user.id,
        user.username = %user.username,
        device.user_agent = %user_agent,
        "[Security Event]: User refreshed their token successfully"
    );

    Ok((headers, Json(LoginOutput { access_token })).into_response())
}

#[instrument(
    name = "user_logout",
    skip(pool, cookies),
    fields(
        security.event = "authentication"
    )
)]
#[utoipa::path(
    get,
    path = "/logout",
    security(
        ("cookie_auth" = [])
    ),
    responses(
        (status = 200, description = "Sends back an empty, expired cookie to client "),
        (status = 401, description = "the refresh_token cookie the user send is messed tf up"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn logout_handler(
    State(pool): State<PgPool>,
    TypedHeader(cookies): TypedHeader<Cookie>,
) -> Result<impl IntoResponse, StatusCode> {
    if cookies.get("refresh_token").is_some_and(|x| x.is_empty())
        || cookies.get("refresh_token").is_none()
    {
        warn!(
            target: "audit",
            action = "auth.logout",
            reason = "no refresh_token provided",
            "[Security Alert]: Failed to log out; no token to revoke provided"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }
    let refresh_cookie = cookies.get("refresh_token").unwrap_or_default();

    let user_id = sqlx::query!(
        "DELETE FROM refresh_tokens WHERE token_hash = $1 RETURNING user_id",
        hash(refresh_cookie)
    )
    .fetch_one(&pool)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: failed to delete refresh_token");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
    .user_id;

    let empty_refresh_cookie =
        "refresh_token=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";

    let mut headers = HeaderMap::new();

    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(empty_refresh_cookie).map_err(|err| {
            error!(error = %err, "failed to adttach new refresh token to headers");
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
    );

    info!(
        target: "audit",
        action = "auth.logout",
        user.id = %user_id,
        "[Security Event]: User logged out"
    );

    Ok((StatusCode::OK, headers).into_response())
}

#[tracing::instrument(
    name = "auth.generate_jwt",
    skip(claims),
    fields(
        user.id = %claims.sub,
        user.username = %claims.username,
        auth.token_type = "JWT"
    )
)]
pub fn generate_jwt(claims: Claims) -> Result<String, StatusCode> {
    let jwt_secret = &SECRETS.jwt_secret;

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .map_err(|err| {
        error!(error = %err, "error encoding jwt");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(token)
}

#[instrument(
    name = "db.insert_refresh_token",
    skip(pool, refresh_token),
    fields(
        user.id = %user_id,
        db.system = "postgresql",
        db.operation = "INSERT",
        db.collection = "refresh_tokens"
    )
)]
pub async fn insert_refresh_token(
    pool: PgPool,
    user_id: Uuid,
    refresh_token: &str,
    user_agent: String,
) -> Result<Uuid, StatusCode> {
    let expires_at = Utc::now() + Duration::days(365);

    debug!(
        user_agent = %user_agent,
        "Hashing and storing new session refresh token"
    );

    let query = sqlx::query!(
        r#"INSERT INTO refresh_tokens (user_id, token_hash, expires_at, user_agent) VALUES ($1, $2, $3, $4) RETURNING id"#,
        user_id,
        hash(refresh_token),
        expires_at,
        user_agent
    )
    .fetch_one(&pool)
    .await
    .map_err(|err| {
        error!(
            error = %err,
            user.id = %user_id,
            "[Database failure]: Failed to write refresh token to database"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(query.id)
}
