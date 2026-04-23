use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{middleware::jwt::AuthenticatedUser, util::secrets::SECRETS};

#[derive(Serialize)]
pub struct Users {
    id: Uuid,
    username: String,
    roles: Value,
}

#[utoipa::path(
    get,
    path = "/admin/users",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "hello admin!!!! hello little stylus, its devinlittle or owen kesterson inside the ADMINNNNNNN", body = String),
        (status = 401, description = "token error i think"),
        (status = 403, description = "you arent supposed to be here STUPID"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "admin"
)]
pub async fn list_users(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<impl IntoResponse, StatusCode> {
    if user.role != "devin" && user.role != "owen" {
        return Err(StatusCode::FORBIDDEN);
    }

    let users = sqlx::query!("SELECT id, username, roles FROM users")
        .fetch_all(&pool)
        .await
        .map_err(|err| {
            tracing::error!("admin fetch all users req failed{}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let users: Vec<Users> = users
        .iter()
        .map(|users| Users {
            id: users.id,
            username: users.username.clone(),
            roles: users.roles.clone(),
        })
        .collect();

    let output = serde_json::to_value(users).map_err(|err| {
        tracing::error!("failed to seriliaze sessions_hashset: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok((Json(output)).into_response())
}

#[derive(Deserialize, ToSchema)]
pub struct ChangeRoleInput {
    #[schema(example = "gradegetter")]
    service: String,
    #[schema(example = "devin")]
    role: String,
}

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
        (status = 200, description = "hello admin!!!! role changed 👀👀👀👀", body = String),
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
    if user.role != "devin" && user.role != "owen" {
        return Err(StatusCode::FORBIDDEN);
    }

    sqlx::query!(
        "UPDATE users
     SET roles = jsonb_set(roles, $1, $2::jsonb)
     WHERE id = $3",
        &[req.service],
        serde_json::json!(req.role),
        target_id
    )
    .execute(&pool)
    .await
    .map_err(|err| {
        tracing::error!("failed to update role: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(().into_response())
}

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
        (status = 200, description = "goodbye user, hello admin", body = String),
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
) -> Result<impl IntoResponse, StatusCode> {
    if user.role != "devin" && user.role != "owen" {
        return Err(StatusCode::FORBIDDEN);
    }

    match sqlx::query!(
        "DELETE FROM refresh_tokens
        WHERE replaced_by_token IS NULL
        AND user_id = $1",
        target_id
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
            tracing::error!(
                "error during attempt to attempt revoking all sessions: {}",
                err
            );
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

pub async fn _force_password_reset(
    State(pool): State<PgPool>,
    Extension(user): Extension<AuthenticatedUser>,
) -> () {
}

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
        (status = 200, description = "goodbye user, hello admin", body = String),
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
    if user.role != "devin" && user.role != "owen" {
        return Err(StatusCode::FORBIDDEN);
    }

    let internal_api_key = &SECRETS.internal_api_key;

    let client = reqwest::Client::new();

    let _ = client
        .get(format!(
            "http://gradegetter_backend:3002/internal/invalidate/{}",
            target_id
        ))
        .header(
            "Authorization",
            format!("Basic {}", internal_api_key.as_str()),
        )
        .send()
        .await
        .map_err(|err| {
            tracing::error!("failed to delete user from gradegetter: {}", err);
        });

    tracing::info!("deleted user: {}", user.username);
    Ok((axum::http::StatusCode::OK).into_response())
}

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
        (status = 200, description = "goodbye user, hello admin", body = String),
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
    if user.role != "devin" && user.role != "owen" {
        return Err(StatusCode::FORBIDDEN);
    }

    let internal_api_key = &SECRETS.internal_api_key;

    match sqlx::query!("DELETE FROM users WHERE id = $1", target_id)
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

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MessageFromFrontend {
    title: String,
    content: String,
}

#[utoipa::path(
    post,
    path = "/admin/global_message",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "goodbye user, hello admin", body = String),
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
    if user.role != "devin" && user.role != "owen" && user.role != "courtney" {
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
        namespace: MessageNamespace::Notification,
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
        .map_err(|err| tracing::error!("failed to send message: {}", err));

    Ok((axum::http::StatusCode::OK).into_response())
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Message {
    pub namespace: MessageNamespace,
    pub payload: serde_json::Value,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MessageNamespace {
    Notification,
    Nanopass,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct NotificationPayload {
    pub r#type: NotificationType,
    pub title: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum NotificationType {
    Global,
    User,
}
