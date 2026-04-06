use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use uuid::Uuid;

use crate::routes::AppState;

#[utoipa::path(
    delete,
    path = "/internal/invalidate/{uuid}",
    params(
        ("uuid", description = "pretty easy to understand what this means.")
    ),
    responses(
        (status = 200, description = "removes uuid from HashSet defined in state, forces checks on next request", body = String),
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
