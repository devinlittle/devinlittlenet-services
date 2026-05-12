use axum::{extract::State, Json};
use common::nanopass::{FileListing, RemoveSessionInternalInput};
use hyper::StatusCode;

use crate::routes::AppState;

#[utoipa::path(
    delete,
    path = "/internal/session_cleanup",
    request_body = RemoveSessionInternalInput,
    security(
        ("internal_auth" = []),
    ),
    responses(
        (status = 200, description = "all listing removed from a specific session_id"),
        (status = 500, description = "uhmmm...failed", body = String),
    ),
    tag = "file_listings"
)]
pub async fn internal_remove_all_session_listings(
    State(state): State<AppState>,
    Json(req): Json<RemoveSessionInternalInput>,
) -> StatusCode {
    let to_remove: Vec<FileListing> = state
        .files
        .iter()
        .filter(|l| l.owner_id == req.user_id && l.session_id == req.session_id)
        .map(|l| l.value().clone())
        .collect();

    state.files.retain(|_, listing| {
        !(listing.owner_id == req.user_id && listing.session_id == req.session_id)
    });

    for listing in &to_remove {
        state
            .broadcast_nanopass_event(
                listing,
                common::nanopass::NanoPassPayload::ListingRemoved {
                    listing: listing.clone(),
                },
            )
            .await
    }

    StatusCode::OK
}
