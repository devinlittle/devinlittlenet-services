use anyhow::Result;
use axum::{
    extract::{ws::Message, Path, State, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use common::{gradegetter::SchoologyLogin, AuthenticatedUser};
use crypto_utils::encrypt_string;
use tokio::sync::watch::{self};
use tracing::{error, info, info_span, instrument, Instrument};
use uuid::Uuid;

use crate::routes::AppState;

#[instrument(
    name = "add_schoology_credentials",
    skip(state, req),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
#[utoipa::path(
    post,
    path = "/auth/schoology/credentials",
    request_body = SchoologyLogin,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 204, description = "Encrypts schoology info and inserts into database"),
        (status = 500, description = "Internal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn add_schoology_credentials_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<SchoologyLogin>,
) -> Result<StatusCode, StatusCode> {
    let encrypted_email = match encrypt_string(&req.schoology_email) {
        Ok(encrypted_email) => encrypted_email,
        Err(err) => {
            error!(error = %err, "[Encryption Error]: failed to encrypt email");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let encrypted_password = match encrypt_string(&req.schoology_password) {
        Ok(encrypted_password) => encrypted_password,
        Err(err) => {
            error!(error = %err, "[Encryption Error]: failed to encrypt password");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let db_span = info_span!("add_schoology_credentials_query");

    sqlx::query!(
        "INSERT INTO schoology_auth (id, encrypted_email, encrypted_password) VALUES ($1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET 
             encrypted_email = EXCLUDED.encrypted_email,
             encrypted_password = EXCLUDED.encrypted_password",
        user.uuid,
        encrypted_email,
        encrypted_password,
    )
    .execute(&state.pool)
    .instrument(db_span)
    .await
    .map_err(|err| {
        error!(error = %err, "[Database failure]: failed to add schoology information to db");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        action = "gradegetter_backend.add_schoology_credentials",
        user.id = %user.uuid,
        user.username = %user.username,
        "Encrypted Schoology Credentials added to user",
    );

    Ok(StatusCode::NO_CONTENT)
}

#[instrument(
    name = "delete_schoology_credentials",
    skip(state),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
#[utoipa::path(
    delete,
    path = "/auth/schoology/credentials",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 204, description = "Encrypts schoology info and inserts into database"),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Internal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn delete_schoology_credentials_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<StatusCode, StatusCode> {
    let db_span = info_span!("delete_schoology_credentials_query");

    sqlx::query!("DELETE FROM schoology_auth WHERE id = $1", user.uuid)
        .execute(&state.pool)
        .instrument(db_span)
        .await
        .map_err(|err| {
            error!(error = %err, "[Database failure]: failed to delete schoology information from db");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    info!(
        action = "gradegetter_backend.delete_schoology_credentials",
        user.id = %user.uuid,
        user.username = %user.username,
        "Encrypted Schoology Credentials removed from user",
    );

    Ok(StatusCode::NO_CONTENT)
}

#[instrument(
    name = "forward_init_to_gradegetter",
    skip(state),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
#[utoipa::path(
    get,
    path = "/auth/forward",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 204, description = "Initilized User on GradeGetter"),
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

#[instrument(
    name = "connect_init_ws",
    skip(ws, state),
    fields(
        user.id = %uuid,
    )
)]
#[utoipa::path(
    get,
    path = "/auth/forward_ws/{id}",
    params(
        ("uuid", description = "pretty easy to understand what this means.")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 204, description = "giving status boy"),
        (status = 401, description = "Credentials Incorrect"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "user_auth"
)]
pub async fn forward_status_for_client(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(uuid): Path<Uuid>,
) -> impl IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        let Some(tx) = state.channels.get(&uuid.to_string()) else {
            return;
        };

        let mut rx = tx.subscribe();
        drop(tx);

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
