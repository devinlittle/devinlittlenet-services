use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::UserRole;

// used in nanopass/routes/internal.rs
#[derive(Serialize, Deserialize, ToSchema)]
pub struct RoleMessage {
    pub target_role: UserRole,
    pub message: String,
}

// used in nanopass/routes/noties.rs
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

#[derive(Serialize, Deserialize, ToSchema)]
pub struct NotificationMessage {
    r#type: NotificationType,
    title: String,
    content: String,
    sender_username: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum NotificationType {
    Global,
    User,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct Bootstrap {
    pub token: String,
    pub session_id: Uuid,
}

#[derive(Serialize, Deserialize, Debug, ToSchema)]
pub struct SendNotification {
    pub recipient: String,
    pub content: String,
}

pub struct PushSubscription {
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}
