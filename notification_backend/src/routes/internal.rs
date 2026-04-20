use std::str::FromStr;

use axum::extract::{Path, State};
use hyper::StatusCode;
use uuid::Uuid;

use crate::routes::AppState;

//#[utoipa::path(get, path = "/internal/global_message")]
pub async fn global_message(State(state): State<AppState>, message: String) -> StatusCode {
    match state.global_channel.send(message) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

//#[utoipa::path(get, path = "/internal/global_message")]
pub async fn user_message(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    message: String,
) -> StatusCode {
    let uuid = match Uuid::from_str(uuid.as_str()) {
        Ok(uuid) => uuid,
        Err(_) => return StatusCode::UNAUTHORIZED,
    };

    let Some(tx) = state.connected_users.get(&uuid) else {return StatusCode::INTERNAL_SERVER_ERROR};

    match tx.send(message) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
