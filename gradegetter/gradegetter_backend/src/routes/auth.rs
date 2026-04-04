use anyhow::Result;
use axum::{Extension, Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use tracing::{error, info};
use utoipa::ToSchema;

use crate::{middleware::jwt::AuthenticatedUser, routes::AppState};

#[derive(Deserialize, ToSchema)]
pub struct SchoologyLogin {
    #[schema(example = "email@exmaple.com")]
    schoology_email: String,
    #[schema(example = "password")]
    schoology_password: String,
}

#[utoipa::path(
    post,
    path = "/auth/schoology/credentials",
    request_body = SchoologyLogin,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Encrypts schoology info and inserts into database", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Internal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn schoology_credentials_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<SchoologyLogin>,
) -> Result<(), StatusCode> {
    info!(
        "Encrypted Schoology Credentials added to user: {:?}",
        user.username
    );

    sqlx::query!(
        "INSERT INTO schoology_auth (id, encrypted_email, encrypted_password) VALUES ($1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET 
             encrypted_email = EXCLUDED.encrypted_email,
             encrypted_password = EXCLUDED.encrypted_password",
        user.uuid,
        crypto_utils::encrypt_string(req.schoology_email.as_str()),
        crypto_utils::encrypt_string(req.schoology_password.as_str()),
    )
    .execute(&state.pool)
    .await
    .map_err(|err| {
        error!(
            "Failed to store Schoology credentials for user {}: {}",
            user.uuid, err
        );
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(())
}

#[utoipa::path(
    get,
    path = "/auth/forward",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Initilized User on GradeGetter", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn foward_to_gradegetter(
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<(), StatusCode> {
    let client = reqwest::Client::new();
    let _ = client
        .post("http://gradegetter:3001/userinit")
        .body(user.uuid.to_string())
        .send()
        .await
        .map_err(|err| {
            error!("failed to initlize user... {}", err);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(())
}

#[utoipa::path(
    delete,
    path = "/auth/internal_delete",
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
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    match sqlx::query!("DELETE FROM service_users WHERE id = $1", user.uuid)
        .execute(&state.pool)
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
