use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "gradegetter")]
pub mod gradegetter;

#[cfg(feature = "nanopass")]
pub mod nanopass;

#[cfg(feature = "notifications")]
pub mod notification;

#[cfg(feature = "smalltalk")]
pub mod smalltalk;

#[derive(Clone, ToSchema, Serialize, Deserialize, Debug)]
pub struct AuthenticatedUser {
    pub username: String,
    pub uuid: uuid::Uuid,
    pub role: UserRole,
}

pub type UserRoles = HashMap<ServiceName, UserRole>;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, ToSchema)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub roles: UserRoles,
    pub public_key: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub iat: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub exp: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Eq, Hash, PartialEq, Clone, Debug, ToSchema, strum::Display)]
//#[serde(rename_all = "snake_case")]
#[serde(rename_all = "lowercase")]
pub enum ServiceName {
    #[serde(alias = "Global")]
    Global,
    #[serde(alias = "Gradegetter")]
    Gradegetter,
    #[serde(alias = "Smalltalk")]
    Smalltalk,
    #[serde(alias = "Notifications")]
    Notifications,
}

#[derive(Serialize, Deserialize, Eq, Hash, PartialEq, Clone, Debug, ToSchema, strum::Display)]
//#[serde(rename_all = "snake_case")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Devin,
    Owen,
    Trusted,
    User,
}

impl UserRole {
    pub fn is_admin(&self) -> bool {
        matches!(self, Self::Devin | Self::Owen)
    }
}

#[derive(Serialize, Deserialize, Eq, Hash, PartialEq, Clone, Debug, ToSchema, strum::Display)]
#[serde(rename_all = "lowercase")]
#[schema(rename_all = "lowercase")]
pub enum Namespaces {
    Notification,
    NanoPass,
    GradeGetter,
    #[serde(rename = "smalltalk_keysync")]
    #[schema(rename = "smalltalk_keysync")]
    SmallTalkKeySync,
    #[serde(rename = "smalltalk_notes")]
    #[schema(rename = "smalltalk_notes")]
    SmallTalkNotes,
}
