use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Namespaces;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[cfg_attr(feature = "smalltalk", derive(sqlx::FromRow))]
pub struct SmalltalkNote {
    pub id: Uuid,
    pub user_id: Uuid,

    // using Vec<u8> for BYTEA columns
    #[schema(value_type = String, format = Binary)]
    pub enc_name: Vec<u8>,

    #[schema(value_type = Option<String>, format = Binary)]
    pub enc_content: Option<Vec<u8>>,

    // Password Protection
    pub is_protected: bool,
    pub password_hash: Option<String>,
    #[schema(value_type = Option<String>, format = Binary)]
    pub salt: Option<Vec<u8>>,

    // Metadata and da UI
    pub rank: i32,
    pub is_deleted: bool,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub updated_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NotePatchRequest {
    #[schema(value_type = Option<String>, format = Binary)]
    pub enc_name: Option<Vec<u8>>,
    #[schema(value_type = Option<String>, format = Binary)]
    pub enc_content: Option<Vec<u8>>,
    pub is_protected: Option<bool>,
    pub password_hash: Option<String>,
    #[schema(value_type = Option<String>, format = Binary)]
    pub salt: Option<Vec<u8>>,
    pub rank: Option<i32>,
    pub is_pinned: Option<bool>,
    pub is_deleted: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SmalltalkNotesMessage {
    pub id: Uuid,
    pub namespace: Namespaces,
    pub payload: SmalltalkNotesEvent,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data")]
pub enum SmalltalkNotesEvent {
    #[schema(rename = "NoteAdded")]
    NoteAdded { note: SmalltalkNote },
    #[schema(rename = "NoteUpdated")]
    NoteUpdated { note_id: Uuid, note: SmalltalkNote },
    #[schema(rename = "NoteDeleted")]
    NoteDeleted { note_id: Uuid },
    #[schema(rename = "NoteRankUpdated")]
    NoteRankUpdated { note_id: Uuid, new_rank: i32 },
    #[schema(rename = "NoteForgotten")]
    NoteForgotten { note_id: Uuid },
}
