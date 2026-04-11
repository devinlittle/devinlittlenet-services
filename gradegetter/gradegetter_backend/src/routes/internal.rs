use axum::{
    extract::{ws::Message, Path, State, WebSocketUpgrade},
    response::IntoResponse,
};
use hyper::StatusCode;
use serde::Deserialize;
use utoipa::ToSchema;
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

#[derive(Deserialize, ToSchema)]
pub struct ForwardMessage {
    id: Uuid,
    status: String,
}

#[utoipa::path(
    get,
    path = "/internal/forward_ws",
    request_body = ForwardMessage,
    responses(
        (status = 200, description = "adding information from gradegetter", body = String),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "internal"
)]
pub async fn forward_status_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|mut socket| async move {
        tracing::debug!("internal ws connected");
        while let Some(Ok(Message::Text(msg))) = socket.recv().await {
            tracing::debug!("internal ws received: {}", msg);
            let payload: ForwardMessage = serde_json::from_str(msg.as_str()).unwrap(); //HACK: 1 unwrap here
            if let Some(tx) = state.channels.get(&payload.id.to_string()) {
                tracing::debug!("found channel for {}, sending", payload.id);
                tx.send(payload.status)
                    .map_err(|err| {
                        tracing::error!("{}", err);
                    })
                    .unwrap(); //HACK: 1 unwrap here
            } else {
                tracing::warn!("no channel found for id: {}", payload.id);
            }
        }
        tracing::debug!("internal ws disconnected");
    })
}
