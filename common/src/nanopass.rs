use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_with::{formats::Strict, serde_as, TimestampSeconds};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Namespaces;

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

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema, PartialEq)]
#[serde(tag = "type")]
pub enum Visibility {
    #[schema(title = "Private")]
    Private,
    #[schema(title = "Public")]
    Public,
    #[schema(title = "Restricted")]
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

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct NanoPassMessage {
    pub namespace: Namespaces,
    pub id: Uuid,
    pub from_session_id: Option<Uuid>, // nullable bc server could send a message
    pub from_user_id: Option<Uuid>,    // nullable cuz server could send a message
    pub target_user_id: Option<Uuid>,  // nullalbe bc the server could send a message
    pub target_session_id: Option<Uuid>, // nullable bc it could be a broadcast or sent from server
    pub payload: NanoPassPayload,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data")]
pub enum NanoPassPayload {
    #[schema(title = "FileQuery")]
    FileQuery {
        listing_id: Uuid,
        requester_session_id: Uuid,
    },
    #[schema(title = "FileQueryResponse")]
    FileQueryResponse {
        listing_id: Uuid,
        host_session_id: Uuid,
    },
    #[schema(title = "TransferRequest")]
    TransferRequest {
        listing_id: Uuid,
        requester_session_id: Uuid,
        requester_username: String,
    },
    #[schema(title = "TransferAccepted")]
    TransferAccepted { listing_id: Uuid },
    #[schema(title = "TransferDeclined")]
    TransferDeclined { listing_id: Uuid },
    #[schema(title = "SDPOffer")]
    SDPOffer { listing_id: Uuid, sdp: String },
    #[schema(title = "SDPAnswer")]
    SDPAnswer { listing_id: Uuid, sdp: String },
    #[schema(title = "ICECandidate")]
    ICECandidate {
        listing_id: Uuid,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u32>,
    },
    #[schema(title = "ListingAdded")]
    ListingAdded { listing: FileListing },
    #[schema(title = "ListingModified")]
    ListingModified { listing: FileListing },
    #[schema(title = "ListingRemoved")]
    ListingRemoved { listing: FileListing },
}
