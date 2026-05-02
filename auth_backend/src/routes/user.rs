use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::{headers::Cookie, TypedHeader};
use chrono::{DateTime, Utc};
use constant_time_eq::constant_time_eq;
use serde::{Deserialize, Serialize};
use sqlx::{types::uuid, PgPool};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    middleware::jwt::{jwt_numeric_date, AuthenticatedUser},
    util::{hash::hash, secrets::SECRETS},
};

#[derive(Deserialize, ToSchema)]
pub struct UpdateProfileInput {
    pub bio: Option<String>,
    pub public_key: Option<String>,
    pub last_seen_visible: Option<bool>,
}

#[utoipa::path(
    patch,
    path = "/me",
    request_body = UpdateProfileInput,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "added public key to db", body = String),
        (status = 401, description = "jwt error"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn add_publickey(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<UpdateProfileInput>,
) -> StatusCode {
    let result = sqlx::query!(
        r#"
        UPDATE users SET
            bio = COALESCE($1, bio),
            public_key = COALESCE($2, public_key),
            last_seen_visible = COALESCE($3, last_seen_visible)
        WHERE id = $4
        "#,
        req.bio,
        req.public_key,
        req.last_seen_visible,
        user.uuid
    )
    .execute(&pool)
    .await;

    match result {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[utoipa::path(
    delete,
    path = "/me",
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
) -> Result<impl IntoResponse, StatusCode> {
    let internal_api_key = &SECRETS.internal_api_key;

    match sqlx::query!("DELETE FROM users WHERE id = $1", user.uuid)
        .execute(&pool)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            let client = reqwest::Client::new();

            let _ = client
                .delete(format!(
                    "http://gradegetter_backend:3002/internal/delete/{}",
                    user.uuid
                ))
                .header(
                    "Authorization",
                    format!("Basic {}", internal_api_key.as_str()),
                )
                .send()
                .await
                .map_err(|err| tracing::error!("failed to delete user from gradegetter: {}", err));

            let _ = client
                .get(format!(
                    "http://gradegetter_backend:3002/internal/invalidate/{}",
                    user.uuid
                ))
                .header(
                    "Authorization",
                    format!("Basic {}", internal_api_key.as_str()),
                )
                .send()
                .await
                .map_err(|err| {
                    tracing::error!("failed to invalidate user from gradegetter: {}", err);
                });

            tracing::info!("deleted user: {}", user.username);
            Ok((axum::http::StatusCode::OK).into_response())
        }
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            tracing::error!("database error: {:?}", err);
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct ActiveSessions {
    session_id: Uuid,
    #[serde(with = "jwt_numeric_date")]
    expires_at: OffsetDateTime,
    user_agent: String,
    is_current: bool,
}

#[utoipa::path(
    get,
    path = "/me/sessions",
    security(
        ("bearer_auth" = []),
        ("cookie_auth" = [])
    ),
    responses(
        (status = 200, description = "shows all the active sessions", body = Vec<ActiveSessions>),
        (status = 401, description = "Credentials Incorrect"),
        (status = 404, description = "Not Found"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn list_active_sessions(
    State(pool): State<PgPool>,
    TypedHeader(cookies): TypedHeader<Cookie>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = sqlx::query!(
        "SELECT id, expires_at, user_agent, token_hash FROM refresh_tokens
        WHERE user_id = $1
        AND replaced_by_token IS NULL",
        user.uuid
    )
    .fetch_all(&pool)
    .await
    .map_err(|err| {
        tracing::error!("failed to grab all active sessions: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let sessions: Vec<ActiveSessions> = sessions
        .iter()
        .map(|session| ActiveSessions {
            session_id: session.id,
            expires_at: session.expires_at.assume_utc(),
            user_agent: session.user_agent.clone(),
            is_current: {
                hash(cookies.get("refresh_token").unwrap_or_default()) == session.token_hash
            },
        })
        .collect();

    let output = serde_json::to_value(sessions).map_err(|err| {
        tracing::error!("failed to seriliaze sessions_hashset: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(output).into_response())
}

#[utoipa::path(
    delete,
    path = "/me/sessions",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "revoked all sessions", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 404, description = "Not Found"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn revoke_all_sessions(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<impl IntoResponse, StatusCode> {
    match sqlx::query!(
        "DELETE FROM refresh_tokens
        WHERE replaced_by_token IS NULL
        AND user_id = $1",
        user.uuid
    )
    .execute(&pool)
    .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                Ok("sessions GONE".into_response())
            } else {
                Err(StatusCode::NOT_MODIFIED)
            }
        }
        Err(err) => {
            tracing::error!("error revoking all sessions: {}", err);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[utoipa::path(
    delete,
    path = "/me/session/{id}",
    params(
        ("id", description = "the id of the specific refesh_token")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "revoked specific token", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 404, description = "Not Found"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn revoke_specific_session(
    State(pool): State<PgPool>,
    Path(path): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<impl IntoResponse, StatusCode> {
    match sqlx::query!(
        "DELETE FROM refresh_tokens
        WHERE replaced_by_token IS NULL
        AND id = $1
        AND user_id = $2",
        path,
        user.uuid,
    )
    .execute(&pool)
    .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                Ok("sessions GONE".into_response())
            } else {
                Err(StatusCode::NOT_MODIFIED)
            }
        }
        Err(err) => {
            tracing::error!("error revoking all sessions: {}", err);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct AddRecoveryInfoInputs {
    pub recovery_hash: String,
    pub encrypted_private_key: String,
}

#[utoipa::path(
    patch,
    path = "/me/recovery",
    request_body = AddRecoveryInfoInputs,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "recovery info added", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 409, description = "information already there")
    ),
    tag = "user_auth"
)]
pub async fn add_recovery_info(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<AddRecoveryInfoInputs>,
) -> Result<impl IntoResponse, StatusCode> {
    match sqlx::query!(
        r#"
        UPDATE users SET
            recovery_hash = COALESCE($1, recovery_hash),
            encrypted_private_key = COALESCE($2, encrypted_private_key)
        WHERE id = $3 "#,
        req.recovery_hash,
        req.encrypted_private_key,
        user.uuid
    )
    .execute(&pool)
    .await
    {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Err(StatusCode::CONFLICT),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyRecoveryInfoInputs {
    pub recovery_hash: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyRecoveryInfoOutputs {
    pub encrypted_private_key: String,
}

#[utoipa::path(
    post,
    path = "/me/recovery/verify",
    request_body = VerifyRecoveryInfoInputs,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "recovery info added", body = VerifyRecoveryInfoOutputs),
        (status = 401, description = "Credentials Incorrect"),
        (status = 403, description = "the hashes do not match"),
        (status = 404, description = "the hashes do not exist"),
    ),
    tag = "user_auth"
)]
pub async fn verify_recovery_info(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<VerifyRecoveryInfoInputs>,
) -> Result<impl IntoResponse, StatusCode> {
    let result = sqlx::query!(
        r#"
        SELECT recovery_hash, encrypted_private_key
        FROM users WHERE id = $1
        "#,
        user.uuid
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| StatusCode::NOT_FOUND)?;

    let recovery_hash = result.recovery_hash.ok_or(StatusCode::NOT_FOUND)?;

    let encrypted_private_key = result.encrypted_private_key.ok_or(StatusCode::NOT_FOUND)?;

    if !constant_time_eq(recovery_hash.as_bytes(), req.recovery_hash.as_bytes()) {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Json(VerifyRecoveryInfoOutputs {
        encrypted_private_key,
    })
    .into_response())
}

#[derive(Serialize, sqlx::FromRow, ToSchema, Debug)]
pub struct UserSearchResult {
    pub id: Uuid,
    pub username: String,
    pub bio: Option<String>,
    pub public_key: Option<String>,
    //    pub last_seen: Option<DateTime<Utc>>,
    //    pub last_seen_visible: bool,
}

#[derive(Deserialize)]
pub struct SearchParams {
    pub q: String,
}

#[utoipa::path(
    post,
    path = "/users/search?q=",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "show user search result", body = Vec<UserSearchResult>),
        (status = 401, description = "Credentials Incorrect"),
        (status = 403, description = "the hashes do not match"),
        (status = 404, description = "the hashes do not exist"),
    ),
    tag = "user_auth"
)]
pub async fn search_user(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(search_query): Query<SearchParams>,
) -> Result<Json<Vec<UserSearchResult>>, StatusCode> {
    if search_query.q.len() < 2 {
        return Ok(Json(vec![]));
    }

    let query = format!("%{}%", search_query.q.trim());

    tracing::debug!("{}", query);

    let results = sqlx::query_as!(
        UserSearchResult,
        r#"
        SELECT id, username, bio, public_key
        FROM users
        WHERE username ILIKE $1
        AND id != $2
        LIMIT 20
        "#,
        query,
        user.uuid
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::debug!("{:?}", results);

    Ok(Json(results))
}
