use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::{headers::Cookie, TypedHeader};
use constant_time_eq::constant_time_eq;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::{types::uuid, PgPool};
use tracing::{error, info, info_span, instrument, warn, Instrument};
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

#[instrument(
    name = "user_add_info",
    skip(pool, req),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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
pub async fn add_account_info(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<UpdateProfileInput>,
) -> StatusCode {
    let db_span = info_span!("add_account_info_query");

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
    .instrument(db_span)
    .await;

    match result {
        Ok(_) => {
            info!(
                action = "auth.add_account_info",
                user.username = %user.username,
                user.id = %user.uuid,
                "[INFO]: Added Info to account!"
            );

            StatusCode::OK
        }
        Err(err) => {
            error!(
                action = "auth.add_account_info",
                error = %err,
                user.username = %user.username,
                user.id = %user.uuid,
                "[ERROR]: Failed to add info to account"
            );

            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[instrument(
    name = "user_deletion",
    skip(pool),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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
    let db_span = info_span!("delete_user_query");

    match sqlx::query!("DELETE FROM users WHERE id = $1", user.uuid)
        .execute(&pool)
        .instrument(db_span)
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

            delete_and_invalidate(
                "http://smalltalk_backend:3005/internal".to_string(),
                &client,
                &user,
            )
            .await;

            info!(
                target: "audit",
                action = "auth.delete",
                user.id = %user.uuid,
                user.username = %user.username,
                "[Security Event]: User deleted their account"
            );

            Ok((axum::http::StatusCode::OK).into_response())
        }
        Ok(_) => {
            warn!(
                target: "audit",
                action = "auth.delete",
                reason = "username_not_found",
                user.username = %user.username,
                user.id= %user.uuid,
                "[Security Alert]: Failed login attempt on non existent username"
            );
            Err(StatusCode::NOT_FOUND)
        }
        Err(err) => {
            error!(error = %err, "[Database failure]: failed attempt to delete user");
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[instrument(
    name = "delete_and_invalidate_from_services",
    skip(client),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
        url = url,
    )
)]
pub async fn delete_and_invalidate(url: String, client: &Client, user: &AuthenticatedUser) {
    // TODO: debug right here
    let _ = client
        .get(format!("{}/invalidate/{}", url, user.uuid))
        .header(
            "Authorization",
            format!("Basic {}", SECRETS.internal_api_key.as_str()),
        )
        .send()
        .await
        .map_err(|err| {
            error!(
                error = %err,
                url = url,
                "[Internal Service failure]: failed to invalidate user"
            );
        });

    // TODO: debug right here
    let _ = client
        .delete(format!("{}/delete/{}", url, user.uuid))
        .header(
            "Authorization",
            format!("Basic {}", SECRETS.internal_api_key.as_str()),
        )
        .send()
        .await
        .map_err(|err| {
            error!(
                error = %err,
                url = url,
                "[Internal Service failure]: failed to delete user"
            );
        });
}

#[instrument(
    name = "invalidate_from_services",
    skip(client),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
        url = url,
    )
)]
pub async fn invalidate(url: String, client: &Client, user: &AuthenticatedUser) {
    // TODO: debug right here
    let _ = client
        .get(format!("{}/invalidate/{}", url, user.uuid))
        .header(
            "Authorization",
            format!("Basic {}", SECRETS.internal_api_key.as_str()),
        )
        .send()
        .await
        .map_err(|err| {
            error!(
                error = %err,
                url = url,
                "[Internal Service failure]: failed to invalidate user"
            );
        });
}

#[instrument(
    name = "user_list_sessions",
    skip(pool, cookies),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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
    let refresh_token = if cookies.get("refresh_token").is_some_and(|x| !x.is_empty()) {
        cookies.get("refresh_token").unwrap_or_default()
    } else {
        warn!(
            action = "auth.list_active_sessions",
            reason = "no refresh_token provided",
            "[Security Alert]: Failed to list active sessions; no token to revoke provided"
        );
        return Err(StatusCode::UNAUTHORIZED);
    };

    let db_span = info_span!("list_active_sessions_query");

    let sessions = sqlx::query!(
        "SELECT id, expires_at, user_agent, token_hash FROM refresh_tokens
        WHERE user_id = $1
        AND revoked_at IS NULL",
        user.uuid
    )
    .fetch_all(&pool)
    .instrument(db_span)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: failed to grab all active sessions");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let sessions: Vec<ActiveSessions> = sessions
        .iter()
        .map(|session| ActiveSessions {
            session_id: session.id,
            expires_at: session.expires_at,
            user_agent: session.user_agent.clone(),
            is_current: { validate(refresh_token, session.token_hash.clone()) },
        })
        .collect();

    let output = serde_json::to_value(sessions).map_err(|err| {
        error!(error = %err, "[Serialization Faliure]: Failed to serialize sessions into output for func");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        action = "auth.list_active_sessions",
        user.id = %user.uuid,
        user.username = %user.username,
        "[INFO]: User retrieved their active sessions successfully"
    );

    Ok(Json(output).into_response())
}

#[instrument(
    name = "user_delete_all_sessions",
    skip(pool),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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
    let db_span = info_span!("revoke_all_sessions_query");

    match sqlx::query!(
        "DELETE FROM refresh_tokens
        WHERE replaced_by_token IS NULL
        AND user_id = $1",
        user.uuid
    )
    .execute(&pool)
    .instrument(db_span)
    .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                info!(
                    target: "audit",
                    action = "auth.token_revoke_all",
                    user.id = %user.uuid,
                    user.username = %user.username,
                    "[Security Event]: User revoked all sessions on their account"
                );
                Ok((StatusCode::OK).into_response())
            } else {
                warn!(
                    target: "audit",
                    action = "auth.token_revoke_all",
                    reason = "username_not_found",
                    user.username = %user.username,
                    user.id= %user.uuid,
                    "[Security Alert]: Failed to revoke sessions, no active sessions? weird bug"
                );
                Err(StatusCode::NOT_MODIFIED)
            }
        }
        Err(err) => {
            error!(error = %err, "[Database failure]: failed attempt to revoke user tokens");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[instrument(
    name = "user_delete_session",
    skip(pool),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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
    let db_span = info_span!("revoke_specific_session_query");

    match sqlx::query!(
        "DELETE FROM refresh_tokens
        WHERE replaced_by_token IS NULL
        AND id = $1
        AND user_id = $2",
        path,
        user.uuid,
    )
    .execute(&pool)
    .instrument(db_span)
    .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                info!(
                    target: "audit",
                    action = "auth.token_specific_revoke",
                    user.id = %user.uuid,
                    user.username = %user.username,
                    "[Security Event]: User revoked a specific session on their account"
                );
                Ok((StatusCode::OK).into_response())
            } else {
                info!(
                    target: "audit",
                    action = "auth.token_specific_revoke",
                    user.id = %user.uuid,
                    user.username = %user.username,
                    "[Security Event]: User revoked a specific session on their account"
                );
                Err(StatusCode::NOT_MODIFIED)
            }
        }
        Err(err) => {
            error!(error = %err, "[Database failure]: failed attempt to revoke a users token");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[instrument(
    name = "user_add_recovery_info",
    skip(pool, req),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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
    let db_span = info_span!("add_recovery_info_db_query");

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
    .instrument(db_span)
    .await
    {
        Ok(_) => {
            //TODO: log
            info!(
                target = "audit",
                action = "auth.add_recovery_info",
                user.id = %user.uuid,
                user.username = %user.username,
                "[Secuirty Event]: User added recovery info"
            );
            Ok(StatusCode::OK)
        }
        Err(err) => {
            error!(error = %err, "[Database failure]: failed to add recovery info");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[instrument(
    name = "user_recovery_info",
    skip(pool, req),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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
    let db_span = info_span!("verify_recovery_info_query");

    let result = sqlx::query!(
        r#"
        SELECT recovery_hash, encrypted_private_key
        FROM users WHERE id = $1
        "#,
        user.uuid
    )
    .fetch_one(&pool)
    .instrument(db_span)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: failure grabbing recovery info from db");
        StatusCode::NOT_FOUND
    })?;

    let recovery_hash = result.recovery_hash.ok_or({
        warn!(
            action = "auth.verify_recovery_info",
            reason = "no_recovery_hash_in_db",
            user.id = %user.uuid,
            user.username = %user.username,
            "[INFO]: No recovery hash is contained in the db"
        );
        StatusCode::NOT_FOUND
    })?;

    let encrypted_private_key = result.encrypted_private_key.ok_or({
        warn!(
            action = "auth.verify_recovery_info",
            reason = "no_privatekey_in_db",
            user.id = %user.uuid,
            user.username = %user.username,
            "[INFO]: No encytped private key is contained in the db"
        );
        StatusCode::NOT_FOUND
    })?;

    if !constant_time_eq(recovery_hash.as_bytes(), req.recovery_hash.as_bytes()) {
        warn!(
            target: "audit",
            action = "auth.verify_recovery_info",
            reason = "invalid_credentials",
            user.id = %user.uuid,
            user.username = %user.username,
            "[INFO]: Failed recovery attempt bc of incorrect credentials"
        );

        return Err(StatusCode::FORBIDDEN);
    }

    info!(
        target: "audit",
        action = "auth.verify_recovery_info",
        user.id = %user.uuid,
        user.username = %user.username,
        "[Security Event]: Gave user encrypted privatekey"
    );

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

#[instrument(
    name = "user_search_by_query",
    skip(pool, search_query),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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

    let db_span = info_span!("search_user_query");

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
    .instrument(db_span)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: failure searching for user");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        action = "auth.search_user",
        user.id = %user.uuid,
        user.username = %user.username,
        "[INFO]: User searched for another"
    );

    Ok(Json(results))
}

// TODO: check if is_admin and then if so send user's roles too!
#[instrument(
    name = "user_search_by_ids",
    skip(pool, req),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
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
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<ByIdsInput>,
) -> Result<Json<Vec<UserSearchResult>>, StatusCode> {
    let db_span = info_span!("get_users_by_ids_query");

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
    .instrument(db_span)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: failure searching for user by id");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        action = "auth.search_user_by_id",
        user.id = %user.uuid,
        user.username = %user.username,
        "[INFO]: User searched for another but by id WOWIE"
    );

    Ok(Json(users))
}
