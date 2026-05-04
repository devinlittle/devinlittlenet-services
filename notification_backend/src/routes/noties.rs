use std::{
    collections::HashSet,
    str::FromStr,
    sync::{Arc, RwLock},
};

use axum::{
    extract::{ws::Message, Path, State, WebSocketUpgrade},
    response::IntoResponse,
    Extension, Json,
};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use tokio::{select, sync::broadcast};
use utoipa::ToSchema;
use uuid::Uuid;
use web_push::{
    ContentEncoding, IsahcWebPushClient, SubscriptionInfo, WebPushClient, WebPushMessageBuilder,
};

use crate::{
    middleware::jwt::AuthenticatedUser,
    routes::{AppState, ConnectedUsers},
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
    Path(path_uuid): Path<String>,
) -> impl IntoResponse {
    ws.on_upgrade(move |mut socket| async move {
        if path_uuid == "global" {
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

        let user = match jwt_parse(axum::extract::State(state.clone()), &bootstrap_json.token).await
        {
            Ok(user) => user,
            Err(_) => return,
        };
        let uuid = match Uuid::from_str(path_uuid.as_str()) {
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

        // Populating online_users per user hashset!!
        if let Some(hashset) = state.online_users.get(&uuid) {
            let mut write = hashset.write().unwrap();
            write.insert(session_id);
            tracing::debug!("Added session to existing active_user entry: {:?}", *write);
        } else {
            let mut new_set = HashSet::new();
            new_set.insert(session_id);
            tracing::debug!("Created new active_user entry: {:?}", new_set);
            state
                .online_users
                .insert(uuid, Arc::new(RwLock::new(new_set)));
        }

        // TODO: set active to true on auth_db thru internal call
        // announce to all users with conversations that user is now active

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

        tokio::spawn(async move {
            let _ = reqwest::Client::new()
                .post("http://nanopass_backend:3004/internal/session_cleanup")
                .header(
                    "Authorization",
                    format!("Basic {}", SECRETS.internal_api_key.as_str()),
                )
                .json(&remove_ses)
                .send()
                .await
                .map_err(|err| tracing::error!("failed to send session cleanup: {}", err));
        });

        // session clean up logic
        tracing::debug!("SESSION REMOVAL LOGIC ABOUT TO RUN");
        let is_empty = if let Some(hashset_ref) = state.online_users.get(&uuid) {
            let mut write = match hashset_ref.write() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("LOCK POISONED FOR USER {}", uuid);
                    poisoned.into_inner()
                }
            };

            write.remove(&session_id);
            write.is_empty()
        } else {
            false
        };

        if is_empty {
            // TODO: add current timestamp as last_active timestamp and active as false
            // announce to all users that account now inactive sending timestamp
            state.online_users.remove(&uuid);
            state.connected_users.remove(&uuid);
            tracing::debug!("No sessions remaining for {}, removing entry", uuid);
        } else {
            tracing::debug!("session_id: {} removed for {}", session_id, uuid);
        }

        tracing::debug!("this is connected_users: {:?}", state.connected_users);
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

    let Some(tx) = state.connected_users.get(&uuid) else { return push_to_browser(state.pool, state.web_push_client, uuid, message).await };

    match tx.send(message.clone()) {
        Ok(_) => StatusCode::OK,
        Err(_) => {
            if notify_user(
                &state.pool,
                &state.web_push_client,
                uuid,
                "a", // TODO: changfe this to be the real title
                message.as_str(),
            )
            .await
            .is_ok()
            {
                StatusCode::OK
            } else {
                tracing::error!("there was an error sending to a usr");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

async fn push_to_browser(
    pool: PgPool,
    web_push_client: IsahcWebPushClient,
    user_id: Uuid,
    message: String,
) -> StatusCode {
    let data: Value = serde_json::from_str(&message).unwrap_or_default();

    match data.get("namespace").and_then(|n| n.as_str()) {
        Some("notification") => {
            let title = data["payload"]["title"].as_str().unwrap_or("");
            let content = data["payload"]["content"].as_str().unwrap_or("");

            if notify_user(
                &pool,
                &web_push_client,
                user_id,
                title, // TODO: changfe this to be the real title
                content,
            )
            .await
            .is_ok()
            {
                StatusCode::OK
            } else {
                tracing::error!("there was an error sending to a usr");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
        _ => StatusCode::NOT_FOUND, // message is not notification-type message
    }
}

#[derive(Deserialize, ToSchema)]
pub struct SubscribeRequest {
    pub endpoint: String,
    pub keys: SubscriptionKeys,
}

#[derive(Deserialize, ToSchema)]
pub struct SubscriptionKeys {
    pub p256dh: String,
    pub auth: String,
}

#[utoipa::path(
    post,
    path = "/subscribe",
    request_body = SubscribeRequest,
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 201, description = "endpoint and keys added to db for user", body = String),
        (status = 500, description = "some server error or whatever", body = String),
    )
)]

pub async fn push_api_subscribe(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<SubscribeRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    sqlx::query!(
        r#"
        INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (endpoint) DO UPDATE
            SET p256dh = EXCLUDED.p256dh,
                auth   = EXCLUDED.auth,
                user_id = EXCLUDED.user_id
        "#,
        user.uuid,
        req.endpoint,
        req.keys.p256dh,
        req.keys.auth,
    )
    .execute(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED).into_response())
}

pub struct PushSubscription {
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

pub async fn get_user_subscriptions(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<PushSubscription>, sqlx::Error> {
    sqlx::query_as!(
        PushSubscription,
        "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = $1",
        user_id
    )
    .fetch_all(pool)
    .await
}

pub async fn notify_user(
    pool: &PgPool,
    client: &IsahcWebPushClient,
    user_id: Uuid,
    title: &str,
    body: &str,
) -> anyhow::Result<()> {
    let subs = get_user_subscriptions(pool, user_id).await?;

    let payload = serde_json::json!({ "title": title, "body": body }).to_string();

    for sub in subs {
        let info = SubscriptionInfo::new(&sub.endpoint, &sub.p256dh, &sub.auth);

        let sig = SECRETS
            .vapid_private_key
            .clone()
            .add_sub_info(&info)
            .build()?;

        let mut builder = WebPushMessageBuilder::new(&info);
        builder.set_payload(ContentEncoding::Aes128Gcm, payload.as_bytes());
        builder.set_vapid_signature(sig);

        match client.send(builder.build()?).await {
            Ok(_) => {}
            Err(web_push::WebPushError::EndpointNotValid(_))
            | Err(web_push::WebPushError::EndpointNotFound(_)) => {
                sqlx::query!(
                    "DELETE FROM push_subscriptions WHERE endpoint = $1",
                    sub.endpoint
                )
                .execute(pool)
                .await?;
            }
            Err(e) => tracing::warn!("Push failed for {}: {}", sub.endpoint, e),
        }
    }

    Ok(())
}

async fn _announce_that_the_user_about_to_be_mentioned_is_now_gonna_be_offline(
    user: Uuid,
    announce_to: Vec<Uuid>,
    channels: &ConnectedUsers,
) -> () {
    for id in announce_to {
        let Some(tx) = channels.get(&id) else {return};

        let message = serde_json::json!({
            "namespace": "smalltalk",
            "payload": {
                "type": "UserOffline",
                "user_id": user
            }
        })
        .to_string();

        match tx.send(message) {
            Ok(_) => (),
            Err(_) => return,
        }
    }
}

async fn _announce_that_the_user_about_to_be_mentioned_is_now_gonna_be_online(
    user: Uuid,
    announce_to: Vec<Uuid>,
    channels: &ConnectedUsers,
) -> () {
    for id in announce_to {
        let Some(tx) = channels.get(&id) else {return};

        let message = serde_json::json!({
            "namespace": "smalltalk",
            "payload": {
                "type": "UserOnline",
                "user_id": user
            }
        })
        .to_string();

        match tx.send(message) {
            Ok(_) => (),
            Err(_) => return,
        }
    }
}
