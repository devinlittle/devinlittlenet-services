use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::{error, info, info_span, instrument, warn, Instrument};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    routes::user::{delete_and_invalidate, invalidate},
    util::secrets::SECRETS,
};

use common::{
    auth::{ChangeRoleInput, Message, NotificationPayload, NotificationType, Users},
    AuthenticatedUser, Namespaces, UserRole,
};

#[instrument(
    name = "admin_list_users",
    skip(pool),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
#[utoipa::path(
    get,
    path = "/admin/users",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "hello admin!!!! hello little stylus, its devinlittle or owen kesterson inside the ADMINNNNNNN", body = Vec<Users>),
        (status = 401, description = "token error i think"),
        (status = 403, description = "you arent supposed to be here STUPID"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "admin"
)]
pub async fn list_users(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<Vec<Users>>, StatusCode> {
    if !user.role.is_admin() {
        warn!(
            action = "auth.admin_list_users",
            reason = "non admin user attempted to access admin route",
            "[Security Alert]: A non admin attempted to access an admin route"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let db_span = info_span!("grab_user_query");

    let users = sqlx::query!("SELECT id, username, roles FROM users")
        .fetch_all(&pool)
        .instrument(db_span)
        .await
        .map_err(|err| {
            error!(error = %err, "[Database failure]: failed to look up users during an admin list user req");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .into_iter()
        .map(|row| {
            Ok(Users {
                id: row.id,
                username: row.username,
                roles: serde_json::from_value(row.roles).map_err(|e| {
                    tracing::error!("error here bubby: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?,
            })
        })
        .collect::<Result<Vec<Users>, StatusCode>>()?;

    info!(
        target: "audit",
        action = "auth.admin_list_users",
        user.id = %user.uuid,
        user.username = %user.username,
        "[Security Event]: Admin retrieved list of all users"
    );

    Ok(Json(users))
}

#[instrument(
    name = "admin_change_user_role",
    skip(pool),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
        target_user.id = %target_id,
        target_user.role = %req.role,
        target_user.service = %req.service
    )
)]
#[utoipa::path(
    patch,
    path = "/admin/users/{id}/role",
    request_body = ChangeRoleInput,
    params(
        ("id", description = "the id of the user to change the role")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "hello admin!!!! role changed 👀👀👀👀"),
        (status = 401, description = "token error i think"),
        (status = 403, description = "you arent supposed to be here IDIIOIOOOOT"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "admin"
)]
pub async fn change_role(
    State(pool): State<PgPool>,
    Path(target_id): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<ChangeRoleInput>,
) -> Result<impl IntoResponse, StatusCode> {
    if !user.role.is_admin() {
        warn!(
            action = "auth.admin_change_user_role",
            reason = "non admin user attempted to access admin route",
            "[Security Alert]: A non admin attempted to access an admin route"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let path = &[req.service.to_string().to_lowercase()];

    let db_span = info_span!("update_user_query");

    sqlx::query!(
        "UPDATE users
     SET roles = jsonb_set(roles, $1, $2::jsonb)
     WHERE id = $3",
        path as &[String],
        serde_json::json!(req.role),
        target_id
    )
    .execute(&pool)
    .instrument(db_span)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: failed to change user role");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        target: "audit",
        action = "auth.admin_change_user_role",
        user.id = %user.uuid,
        user.username = %user.username,
        target_user.id = %target_id,
        "[Security Event]: Admin changed a user's role"
    );

    Ok((StatusCode::OK).into_response())
}

#[instrument(
    name = "admin_revoke_all_sessions_from_id",
    skip(pool),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
        target_user.id = %target_id
    )
)]
#[utoipa::path(
    delete,
    path = "/admin/revoke_all/{id}",
    params(
        ("id", description = "the id of the user to revoke all refresh_tokens from")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "goodbye user, hello admin"),
        (status = 401, description = "token error i think"),
        (status = 403, description = "you arent supposed to be here IDIIOIOOOOT"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "admin"
)]
pub async fn revoke_all_from_id(
    State(pool): State<PgPool>,
    Path(target_id): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<String, StatusCode> {
    if !user.role.is_admin() {
        warn!(
            action = "auth.admin_revoke_all_sessions_from_id",
            reason = "non admin user attempted to access admin route",
            "[Security Alert]: A non admin attempted to access an admin route"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let db_span = info_span!("delete_refresh_query");

    match sqlx::query!(
        "DELETE FROM refresh_tokens
        WHERE replaced_by_token IS NULL
        AND user_id = $1",
        target_id
    )
    .execute(&pool)
    .instrument(db_span)
    .await
    {
        Ok(result) => {
            if result.rows_affected() > 0 {
                info!(
                    target: "audit",
                    action = "auth.admin_revoke_all_sessions_from_id",
                    user.id = %user.uuid,
                    user.username = %user.username,
                    target_user.id = %target_id,
                    "[Security Event]: Admin deauthed a user"
                );

                Ok("sessions GONE".to_string())
            } else {
                info!(
                    target: "audit",
                    action = "auth.admin_revoke_all_sessions_from_id",
                    user.id = %user.uuid,
                    user.username = %user.username,
                    target_user.id = %target_id,
                    "[Security Event]: Admin attempted to deauth user; no active sessions"
                );
                Err(StatusCode::NOT_MODIFIED)
            }
        }
        Err(err) => {
            error!(error = %err, "[Database failure]: revoke all users' session tokens during admin req");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

// TODO: make this a thing
pub async fn _force_password_reset(
    State(_pool): State<PgPool>,
    Extension(_user): Extension<AuthenticatedUser>,
) -> () {
}

#[instrument(
    name = "admin_evict_from_hashset",
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
        target_user.id = %target_id
    )
)]
#[utoipa::path(
    post,
    path = "/admin/users/{id}/evict",
    params(
        ("id", description = "the id of the user to evict from service hashsets")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "goodbye user, hello admin"),
        (status = 401, description = "token error i think"),
        (status = 403, description = "you arent supposed to be here IDIIOIOOOOT"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "admin"
)]
pub async fn evict_from_hashset(
    Path(target_id): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<impl IntoResponse, StatusCode> {
    if !user.role.is_admin() {
        warn!(
            action = "auth.admin_evict_from_hashset",
            reason = "non admin user attempted to access admin route",
            "[Security Alert]: A non admin attempted to access an admin route"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let client = reqwest::Client::new();

    invalidate(
        "http://gradegetter_backend:3002/internal".to_string(),
        &client,
        &user,
    )
    .await;

    invalidate(
        "http://notification_backend:3003/internal".to_string(),
        &client,
        &user,
    )
    .await;

    invalidate(
        "http://smalltalk_backend:3005/internal".to_string(),
        &client,
        &user,
    )
    .await;

    info!(
        target: "audit",
        action = "auth.admin_evict_from_hashset",
        user.id = %user.uuid,
        user.username = %user.username,
        target_user.id = %target_id,
        "[Security Event]: Admin evicted user form all hashsets"
    );

    Ok((axum::http::StatusCode::OK).into_response())
}

#[instrument(
    name = "admin_delete_user_by_id",
    skip(pool),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
        target_user.id = %target_id
    )
)]
#[utoipa::path(
    delete,
    path = "/admin/users/{id}/delete",
    params(
        ("id", description = "the id of the user to delete")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "goodbye user, hello admin"),
        (status = 401, description = "token error i think"),
        (status = 403, description = "you arent supposed to be here IDIIOIOOOOT"),
        (status = 404, description = "user not found"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "admin"
)]
pub async fn delete_by_id(
    State(pool): State<PgPool>,
    Path(target_id): Path<Uuid>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<impl IntoResponse, StatusCode> {
    if !user.role.is_admin() {
        warn!(
            action = "auth.admin_delete_user_by_id",
            reason = "non admin user attempted to access admin route",
            "[Security Alert]: A non admin attempted to access an admin route"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let db_span = info_span!("delete_user_query");

    match sqlx::query!("DELETE FROM users WHERE id = $1", target_id)
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

            info!(
                target: "audit",
                action = "auth.admin_delete_user_by_id",
                user.id = %user.uuid,
                user.username = %user.username,
                target_user.id = %target_id,
                "[Security Event]: Admin deleted a user's account"
            );

            Ok((axum::http::StatusCode::OK).into_response())
        }
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            error!(error = %err, "[Database failure]: failed to delete user during admin req");
            Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MessageFromFrontend {
    title: String,
    content: String,
}

#[instrument(
    name = "admin_global_message",
    skip(req),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
#[utoipa::path(
    post,
    path = "/admin/global_message",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "goodbye user, hello admin"),
        (status = 401, description = "token error i think"),
        (status = 403, description = "you arent supposed to be here IDIIOIOOOOT"),
        (status = 404, description = "user not found"),
        (status = 500, description = "Interal Server Error")
    ),
    request_body = MessageFromFrontend,
    tag = "admin"
)]
pub async fn global_message(
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<MessageFromFrontend>,
) -> Result<impl IntoResponse, StatusCode> {
    if user.role == UserRole::User {
        warn!(
            action = "auth.admin_global_message",
            reason = "non trusted user attempted to access trusted route",
            "[Security Alert]: A non trusted user attempted to access an admin route"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    let internal_api_key = &SECRETS.internal_api_key;

    let client = reqwest::Client::new();

    let payload = NotificationPayload {
        r#type: NotificationType::Global,
        title: req.title,
        content: req.content,
    };

    let payload = serde_json::to_value(payload).unwrap_or_default();

    let message = Message {
        namespace: Namespaces::Notification,
        payload,
    };

    let _ = client
        .post("http://notification_backend:3003/internal/global_message")
        .header(
            "Authorization",
            format!("Basic {}", internal_api_key.as_str()),
        )
        .json(&message)
        .send()
        .await
        .map_err(|err| {
            error!(error = %err, "[Internal Service failure]: failed to send global_message from admin route");
        });

    info!(
        target: "audit",
        action = "auth.admin_global_message",
        user.id = %user.uuid,
        user.username = %user.username,
        "[INFO]: admin sent a global message"
    );

    Ok((axum::http::StatusCode::OK).into_response())
}
