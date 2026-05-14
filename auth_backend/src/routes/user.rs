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
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::{types::uuid, PgPool};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::util::{hash::validate, secrets::SECRETS};

use common::{
    auth::{
        ActiveSessions, AddRecoveryInfoInputs, ByIdsInput, UpdateProfileInput,
        VerifyRecoveryInfoInputs, VerifyRecoveryInfoOutputs,
    },
    AuthenticatedUser,
};

#[utoipa::path(
    patch,
    path = "/me",
    request_body = UpdateProfileInput,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "added public key to db"),
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
        (status = 200, description = "Deleted User"),
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
    match sqlx::query!("DELETE FROM users WHERE id = $1", user.uuid)
        .execute(&pool)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            let client = reqwest::Client::new();

            delete_and_invalidate(
                "http://gradegetter_backend:3002/internal".to_string(),
                &client,
                &user,
            )
            .await;

            delete_and_invalidate(
                "http://notification_backend:3003/internal".to_string(),
                &client,
                &user,
            )
            .await;

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

pub async fn delete_and_invalidate(url: String, client: &Client, user: &AuthenticatedUser) {
    let _ = client
        .delete(format!("{}/delete/{}", url, user.uuid))
        .header(
            "Authorization",
            format!("Basic {}", SECRETS.internal_api_key.as_str()),
        )
        .send()
        .await
        .map_err(|err| {
            tracing::error!(
                "failed to delete user from service with url {}: {}",
                url,
                err
            )
        });

    let _ = client
        .get(format!("{}/invalidate/{}", url, user.uuid))
        .header(
            "Authorization",
            format!("Basic {}", SECRETS.internal_api_key.as_str()),
        )
        .send()
        .await
        .map_err(|err| {
            tracing::error!(
                "failed to invalidate user from service with url {}: {}",
                url,
                err
            );
        });
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
    let refresh_token = if cookies.get("refresh_token").is_some() {
        cookies.get("refresh_token").unwrap_or_default()
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let sessions = sqlx::query!(
        "SELECT id, expires_at, user_agent, token_hash FROM refresh_tokens
        WHERE user_id = $1
        AND revoked_at IS NULL",
        user.uuid
    )
    .fetch_all(&pool)
    .await
    .map_err(|err| {
        tracing::error!("failed to grab all active sessions: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    #[allow(clippy::redundant_closure)]
    let sessions: Vec<ActiveSessions> = sessions
        .iter()
        .map(|session| ActiveSessions {
            session_id: session.id,
            expires_at: DateTime::from_timestamp(
                session.expires_at.assume_utc().unix_timestamp(),
                0,
            )
            .unwrap_or_else(|| Utc::now()),
            user_agent: session.user_agent.clone(),
            is_current: {
                validate(
                    refresh_token,
                    session.token_hash.clone().unwrap_or_default(),
                )
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
        (status = 200, description = "revoked all sessions"),
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
                Ok((StatusCode::OK).into_response())
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
        (status = 200, description = "revoked specific token"),
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
                Ok((StatusCode::OK).into_response())
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
    patch,
    path = "/me/recovery",
    request_body = AddRecoveryInfoInputs,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "recovery info added"),
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
    get,
    path = "/users/search",
    params(("q", Query, description = "the user search query")),
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

// TODO: check if is_admin and then if so send user's roles too!
#[utoipa::path(
    post,
    path = "/users/by-ids",
    request_body = ByIdsInput,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "shows userinfo with provided ids", body = Vec<UserSearchResult>),
        (status = 401, description = "Credentials Incorrect"),
        (status = 403, description = "the hashes do not match"),
        (status = 404, description = "the hashes do not exist"),
    ),
    tag = "user_auth"
)]
pub async fn get_users_by_ids(
    State(pool): State<PgPool>,
    Extension(_user): Extension<AuthenticatedUser>,
    Json(req): Json<ByIdsInput>,
) -> Result<Json<Vec<UserSearchResult>>, StatusCode> {
    let users = sqlx::query_as!(
        UserSearchResult,
        r#"
        SELECT id, username, bio, public_key
        FROM users
        WHERE id = ANY($1)
        "#,
        &req.ids as &[Uuid]
    )
    .fetch_all(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(users))
}
