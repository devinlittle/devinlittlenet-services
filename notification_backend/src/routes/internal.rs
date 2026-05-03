use std::str::FromStr;

use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use uuid::Uuid;

use crate::routes::AppState;

#[utoipa::path(
    get,
    path = "/internal/invalidate/{uuid}",
    params(
        ("uuid", description = "pretty easy to understand what this means.")
    ),
    responses(
        (status = 200, description = "Removes uuid from HashSet defined in state, forces checks on next request", body = String),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "internal"
)]
pub async fn invalidate_user(
    State(state): State<AppState>,
    Path(uuid): Path<Uuid>,
) -> Result<String, StatusCode> {
    let seen_users = &state.seen_users;

    let mut write = seen_users.write().map_err(|err| {
        tracing::error!("{}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    tracing::debug!("hashset before remove: {:?}", *write);
    tracing::debug!("attempting to remove: {}", uuid);
    write.remove(&uuid);
    tracing::debug!("hashset after remove: {:?}", *write);

    drop(write);

    Ok(format!("Removed {} from `seen_users` HashSet", uuid).to_string())
}

#[utoipa::path(
    delete,
    path = "/internal/delete/{uuid}",
    params(
        ("uuid", description = "pretty easy to understand what this means.")
    ),
    responses(
        (status = 200, description = "removes user from the lazily created db", body = String),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "internal"
)]
pub async fn delete_handler(
    State(state): State<AppState>,
    Path(uuid): Path<Uuid>,
) -> impl IntoResponse {
    match sqlx::query!("DELETE FROM service_users WHERE id = $1", uuid)
        .execute(&state.pool)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            tracing::info!("deleted user: {}", uuid);
            axum::http::StatusCode::OK
        }
        Ok(_) => StatusCode::NOT_FOUND,
        Err(err) => {
            tracing::error!("database error: {:?}", err);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[utoipa::path(
    get,
    path = "/internal/global_message",
    security(
        ("internal_auth" = []),
    ),
    responses(
        (status = 200, description = "message send and broadcasted", body = String),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "internal"
)]
pub async fn global_message(State(state): State<AppState>, message: String) -> StatusCode {
    match state.global_channel.send(message) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[utoipa::path(
    get,
    path = "/internal/user_message/{uuid}",
    params(
        ("uuid", description = "pretty easy to understand what this means.")
    ),
    security(
        ("internal_auth" = []),
    ),
    responses(
        (status = 200, description = "message send and broadcasted", body = String),
        (status = 404, description = "channel that was request to send to not found", body = String),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "internal"
)]
pub async fn user_message(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    message: String,
) -> StatusCode {
    let uuid = match Uuid::from_str(uuid.as_str()) {
        Ok(uuid) => uuid,
        Err(_) => return StatusCode::UNAUTHORIZED,
    };

    let Some(tx) = state.connected_users.get(&uuid) else {return StatusCode::NOT_FOUND};

    match tx.send(message) {
        Ok(_) => StatusCode::OK,
        Err(_) => {
            tracing::error!("USER NOT ONLINE");
            // push notification out
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
