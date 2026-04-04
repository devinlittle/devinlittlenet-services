use axum::extract::{Path, State};
use hyper::StatusCode;
use uuid::Uuid;

use crate::routes::AppState;

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
