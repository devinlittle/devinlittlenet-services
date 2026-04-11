use anyhow::Result;
use axum::{
    extract::{ws::Message, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use tokio::sync::watch::{self};
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
        (status = 204, description = "Encrypts schoology info and inserts into database", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Internal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn add_schoology_credentials_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<SchoologyLogin>,
) -> Result<StatusCode, StatusCode> {
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

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/auth/schoology/credentials",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 204, description = "Encrypts schoology info and inserts into database", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Internal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn delete_schoology_credentials_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<StatusCode, StatusCode> {
    info!(
        "Encrypted Schoology Credentials removed from user: {:?}",
        user.username
    );

    sqlx::query!("DELETE FROM schoology_auth WHERE id = $1", user.uuid)
        .execute(&state.pool)
        .await
        .map_err(|err| {
            error!(
                "Failed to delete Schoology credentials for user {}: {}",
                user.uuid, err
            );
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/auth/forward",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 204, description = "Initilized User on GradeGetter", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn foward_to_gradegetter(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<StatusCode, StatusCode> {
    let (tx, rx) = watch::channel(user.uuid.to_string());
    state.channels.insert(user.uuid.to_string(), tx);

    let uuid = user.uuid.to_string();
    let channels = state.channels.clone();

    tokio::spawn(async move {
        let _rx = rx; // keeps receiver alive for the entire job
        let client = reqwest::Client::new();
        let result = client
            .post("http://gradegetter:3001/userinit")
            .body(uuid.clone())
            .send()
            .await;

        match result {
            Ok(res) => tracing::info!("gradegetter responded: {}", res.status()),
            Err(e) => tracing::error!("failed to initialize user: {e}"),
        }

        channels.remove(&uuid)
    });

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/auth/forward_ws",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 204, description = "giving status boy", body = String),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn forward_status_for_client(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    ws.on_upgrade(|mut socket| async move {
        let Some(tx) = state.channels.get(&user.uuid.to_string()) else {
            return;
        };

        let mut rx = tx.subscribe();
        drop(tx);
        drop(user);

        while rx.changed().await.is_ok() {
            let msg = rx.borrow_and_update().clone();
            if socket.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    })
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
