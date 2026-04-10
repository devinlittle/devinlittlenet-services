use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};
use hyper::StatusCode;
use reqwest::ClientBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::middleware::jwt::AuthenticatedUser;

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

    let internal_api_key =
        dotenvy::var("INTERNAL_API_KEY").expect("INTERNAL_API_KEY env var missing");

    let client = reqwest::Client::new();

    let _ = client
        .delete(format!(
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
