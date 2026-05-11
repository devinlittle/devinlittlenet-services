use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{ServiceName, UserRole, UserRoles};

// used in auth_backend/src/routes/admin.rs
#[derive(Serialize, ToSchema, Debug, Clone)]
pub struct Users {
    pub id: Uuid,
    pub username: String,
    pub roles: UserRoles,
}

#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub struct ChangeRoleInput {
    #[schema(example = "gradegetter")]
    pub service: ServiceName,
    #[schema(example = "devin")]
    pub role: UserRole,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct Message {
    pub namespace: MessageNamespace,
    pub payload: serde_json::Value,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MessageNamespace {
    Notification,
    Nanopass,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct NotificationPayload {
    pub r#type: NotificationType,
    pub title: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum NotificationType {
    Global,
    User,
}

// used in auth_backend/src/routes/auth.rs

#[derive(Deserialize, ToSchema)]
pub struct RegisterInput {
    #[schema(example = "user")]
    pub username: String,
    #[schema(example = "password")]
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginInput {
    #[schema(example = "user")]
    pub username: String,
    #[schema(example = "password")]
    pub password: String,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct LoginOutput {
    pub access_token: String,
}

// used in auth_backend/src/routes/user.rs

#[derive(Deserialize, ToSchema)]
pub struct UpdateProfileInput {
    pub bio: Option<String>,
    pub public_key: Option<String>,
    pub last_seen_visible: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct ActiveSessions {
    pub session_id: Uuid,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub expires_at: DateTime<Utc>,
    pub user_agent: String,
    pub is_current: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct AddRecoveryInfoInputs {
    pub recovery_hash: String,
    pub encrypted_private_key: String,
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyRecoveryInfoInputs {
    pub recovery_hash: String,
}

#[derive(Serialize, ToSchema)]
pub struct VerifyRecoveryInfoOutputs {
    pub encrypted_private_key: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ByIdsInput {
    pub ids: Vec<Uuid>,
}
