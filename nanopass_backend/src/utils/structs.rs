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
