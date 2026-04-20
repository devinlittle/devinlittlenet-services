use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::middleware::jwt::jwt_numeric_date;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
#[serde(tag = "type")]
pub enum Visibility {
    Private,
    Public,
    Restricted { allowlist: Vec<Uuid> },
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct FileListing {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub session_id: Uuid,
    pub filename: String,
    pub size_bytes: u64,
    pub mime_type: String,
    #[serde(with = "jwt_numeric_date")]
    pub created_at: OffsetDateTime,
    pub visibility: Visibility,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FileListingInput {
    pub owner_id: Uuid,
    pub session_id: Uuid,
    pub filename: String,
    pub size_bytes: u64,
    pub mime_type: String,
    #[serde(with = "jwt_numeric_date")]
    pub created_at: OffsetDateTime,
    pub visibility: Visibility,
}

/* struct NanoPassMessage {
    id: Uuid,
    from_session_id: Uuid,
    target_session_id: Option<Uuid>,
    payload: NanoPassPayload,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum NanoPassPayload {
    FileQuery {
        listing_id: Uuid,
        requester_session_id: Uuid,
    },
    FileQueryResponse {
        listing_id: Uuid,
        host_session_id: Uuid,
    },
    TransferRequest {
        listing_id: Uuid,
        requester_session_id: Uuid,
    },
    TransferAccepted {
        listing_id: Uuid,
    },
    TransferDeclined {
        listing_id: Uuid,
    },
    SDPOffer {
        listing_id: Uuid,
        sdp: String,
    },
    SDPAnswer {
        listing_id: Uuid,
        sdp: String,
    },
    ICECandidate {
        listing_id: Uuid,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
    ListingAdded {
        listing: FileListing,
    },
    ListingRemoved {
        listing_id: Uuid,
    },
} */
