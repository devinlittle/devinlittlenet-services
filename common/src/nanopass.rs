use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{formats::Strict, serde_as, TimestampSeconds};
use utoipa::ToSchema;
use uuid::Uuid;

// used in nanopass/routes/files.rs
#[derive(Deserialize, ToSchema)]
pub struct RemoveListingInput {
    pub listing_id: Uuid,
}

#[derive(Deserialize, ToSchema)]
pub struct RemoveSessionInput {
    pub session_id: Uuid,
}

// used in nanopass/routes/internal.rs
#[derive(Serialize, Deserialize, ToSchema)]
pub struct RemoveSessionInternalInput {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

// nanopass structs

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(tag = "type")]
pub enum Visibility {
    Private,
    Public,
    Restricted { allowlist: Vec<Uuid> },
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct FileListing {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub owner_username: String,
    pub session_id: Uuid,
    pub filename: String,
    pub size_bytes: u64,
    pub mime_type: String,
    #[serde_as(as = "TimestampSeconds<String, Strict>")]
    pub created_at: DateTime<Utc>,
    pub visibility: Visibility,
    pub auto_accept: bool,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FileListingInput {
    pub owner_id: Uuid,
    pub session_id: Uuid,
    pub filename: String,
    pub size_bytes: u64,
    pub mime_type: String,
    #[serde_as(as = "TimestampSeconds<String, Strict>")]
    pub created_at: DateTime<Utc>,
    pub visibility: Visibility,
    pub auto_accept: bool,
}
