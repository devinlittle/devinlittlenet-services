use axum::extract::State;
use hyper::StatusCode;

use crate::routes::AppState;

//#[utoipa::path(get, path = "/internal/global_message")]
pub async fn global_message(State(state): State<AppState>, message: String) -> StatusCode {
    match state.global_channel.send(message) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
