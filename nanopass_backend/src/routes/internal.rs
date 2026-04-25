use axum::{extract::State, Json};
use hyper::StatusCode;
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    routes::{files::notify_listing_removed, AppState},
    utils::{secrets::SECRETS, structs::FileListing},
};

#[derive(Deserialize, ToSchema)]
pub struct RemoveSessionInternalInput {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

#[utoipa::path(
    delete,
    path = "/internal/session_cleanup",
    request_body = RemoveSessionInternalInput,
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "all listing removed from a specific session_id", body = String),
        (status = 500, description = "uhmmm...failed", body = String),
    ),
    tag = "file_listings"
)]
pub async fn remove_all_session_listings(
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
        notify_listing_removed(listing, &state.client, &SECRETS.internal_api_key).await;
    }

    StatusCode::OK
}
