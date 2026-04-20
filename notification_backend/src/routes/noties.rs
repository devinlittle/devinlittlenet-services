use std::str::FromStr;

use axum::{
    extract::{ws::Message, Path, State, WebSocketUpgrade},
    response::IntoResponse,
};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::{select, sync::broadcast};
use uuid::Uuid;

use crate::{
    routes::AppState,
    utils::{jwt::jwt_parse, secrets::SECRETS},
};

#[utoipa::path(
    get,
    path = "/ws/{id}",
    params(
        ("String", description = "contains 'global' or a uuid")
    ),
    responses(
        (status = 101, description = "swithcing to websockets", body = String),
    )
)]
pub async fn notify(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        if uuid == "global" {
            let mut global_rx = state.global_channel.subscribe();
            while let Ok(msg) = global_rx.recv().await {
                if socket.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
            return;
        }

        // Intial process
        // First message needs to be a BOOTSTRAP w/ token
        let Some(Ok(Message::Text(msg))) = socket.recv().await else { return; };
        if !msg.contains("BOOTSTRAP") {
            return;
        }
        let Some(bootstrap_json) = msg.find(":").map(|x| &msg[x + 1..]) else { return; };

        let Ok(bootstrap_json) = serde_json::from_str::<Bootstrap>(bootstrap_json) else { return; };

        let user = match jwt_parse(&bootstrap_json.token).await {
            Ok(user) => user,
            Err(_) => return,
        };
        let uuid = match Uuid::from_str(uuid.as_str()) {
            Ok(uuid) => uuid,
            Err(_) => return,
        };

        if user.uuid != uuid {
            socket
                .send(
                    format!(
                        "UUID in Token doesn't match with websocket path; {} != {}",
                        user.uuid, uuid
                    )
                    .into(),
                )
                .await
                .unwrap_or_default();
            return;
        }

        let session_id = bootstrap_json.session_id;

        if !state.connected_users.contains_key(&uuid) {
            let (tx, _) = broadcast::channel::<String>(32);
            state.connected_users.insert(uuid, tx);
        }
        socket
            .send(Message::Text("Channel Created".into()))
            .await
            .ok();

        // From this line forward, user is in connected_users and the endpoint is setup
        let mut global_rx = state.global_channel.subscribe();
        let tx = if let Some(tx) = state.connected_users.get(&uuid) {
            tx.subscribe()
        } else {
            let (tx, _) = broadcast::channel(32);
            state.connected_users.insert(uuid, tx.clone());
            state.connected_users.get(&uuid).unwrap().subscribe()
        };
        let mut user_rx = tx;

        loop {
            select! {
                msg = socket.recv() => {
                        let msg = match msg {
                            Some(Ok(msg)) => msg,
                            _ => break,
                        };
                        let msg = msg.to_text().unwrap_or_default();

                        let send_req = match serde_json::from_str::<SendNotification>(msg) {
                            Ok(send_req) => send_req,
                            Err(_) => break,
                        };

                        let recipient_uuid = match Uuid::from_str(send_req.recipient.as_str()) {
                            Ok(recipient_uuid) => recipient_uuid,
                            Err(_) => break,
                        };

                        if let Some(tx) = state.connected_users.get(&recipient_uuid) {
                            tx.send(send_req.content)
                              .map_err(|err| tracing::error!("error sending to user_tx: {}", err))
                              .ok();
                        }
                        tracing::trace!("This is a send request");
                },
                msg = global_rx.recv() => {
                    match msg {
                        Ok(msg) => {
                            if socket.send(Message::Text(msg.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                },
                msg = user_rx.recv() => {
                    match msg {
                        Ok(msg) => {
                            if socket.send(Message::Text(msg.into())).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                },
            }
        }

        let remove_ses = RemoveSessionInternalInput {
            user_id: user.uuid,
            session_id,
        };

        let _ = reqwest::Client::new()
            .post("http://nanopass_backend:3004/internal/session_cleanup")
            .header(
                "Authorization",
                format!("Basic {}", SECRETS.internal_api_key.as_str()),
            )
            .json(&remove_ses)
            .send()
            .await
            .map_err(|err| tracing::error!("failed to send message: {}", err));

        // Pruning disconnecting user from connected users
        let should_remove = state
            .connected_users
            .get(&uuid)
            .map(|user_tx| {
                tracing::trace!("receiver_count for {}: {}", uuid, user_tx.receiver_count());
                user_tx.receiver_count() == 0
            })
            .unwrap_or(false);

        if should_remove {
            state.connected_users.remove(&uuid);
            tracing::trace!("Removed {} from connected_users", uuid);
        }
    })
}

#[derive(Serialize, Deserialize, Debug)]
struct Bootstrap {
    token: String,
    session_id: Uuid,
}

#[derive(Serialize, Deserialize, Debug)]
struct SendNotification {
    recipient: String,
    content: String,
}

#[derive(Serialize)]
pub struct RemoveSessionInternalInput {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/user_message/{id}",
    request_body = String,
    params(
        ("String", description = "contains a uuid")
    ),
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "message sent to channel", body = String),
        (status = 401, description = "uuid can't be parsed; JWT error", body = String),
        (status = 500, description = "some server error or whatever", body = String),
    )
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

    let Some(tx) = state.connected_users.get(&uuid) else {return StatusCode::INTERNAL_SERVER_ERROR};

    match tx.send(message) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
