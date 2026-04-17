use std::str::FromStr;

use axum::{
    extract::{ws::Message, Path, State, WebSocketUpgrade},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tokio::{select, sync::broadcast};
use uuid::Uuid;

use crate::{routes::AppState, utils::jwt::jwt_parse};

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
            if let Ok(msg) = global_rx.recv().await && socket.send(Message::Text(msg.into())).await.is_err() {
                return;
            }
            return;
        }

        // Intial process
        // First message needs to be a BOOTSTRAP w/ token
        let Some(Ok(Message::Text(msg))) = socket.recv().await else { return; };
        if !msg.contains("BOOTSTRAP") {
            return;
        }
        let Some(token) = msg.find(":").map(|x| &msg[x + 1..]) else { return; };
        let _ = match jwt_parse(token).await {
            Ok(user) => user,
            Err(_) => return,
        };
        let uuid = match Uuid::from_str(uuid.as_str()) {
            Ok(uuid) => uuid,
            Err(_) => return,
        };
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
        // Pruning disconnecting user from connected users
        let should_remove = state.connected_users
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
struct SendNotification {
    recipient: String,
    content: String,
}
