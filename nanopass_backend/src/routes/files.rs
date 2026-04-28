use axum::{extract::State, response::IntoResponse, Extension, Json};
use hyper::StatusCode;
use serde::Deserialize;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    middleware::jwt::AuthenticatedUser,
    routes::AppState,
    utils::{
        secrets::SECRETS,
        structs::{FileListing, FileListingInput, Visibility},
    },
};

#[utoipa::path(
    post,
    path = "/listings",
    request_body = FileListingInput,
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "listing created", body = FileListing),
        (status = 500, description = "uhmmm...failed", body = String),
    ),
    tag = "file_listings"
)]
pub async fn create_listing(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<FileListingInput>,
) -> impl IntoResponse {
    let file_listing = FileListing {
        id: Uuid::new_v4(),
        owner_id: user.uuid,
        owner_username: user.username,
        session_id: req.session_id,
        filename: req.filename,
        size_bytes: req.size_bytes,
        mime_type: req.mime_type,
        created_at: OffsetDateTime::now_utc(),
        visibility: req.visibility,
    };

    if state
        .files
        .insert(file_listing.id, file_listing.clone())
        .is_none()
    {
        notify_listing_added(&file_listing, &state.client, &SECRETS.internal_api_key).await;
        Json(file_listing).into_response()
    } else {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RemoveListingInput {
    pub listing_id: Uuid,
}

#[utoipa::path(
    delete,
    path = "/listings",
    request_body = RemoveListingInput,
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "listing removed", body = String),
        (status = 500, description = "uhmmm...failed", body = String),
    ),
    tag = "file_listings"
)]
pub async fn remove_listing(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<RemoveListingInput>,
) -> StatusCode {
    match state.files.get(&req.listing_id) {
        Some(listing) if listing.owner_id == user.uuid => {
            let owned = listing.clone();
            drop(listing);
            state.files.remove(&req.listing_id);
            notify_listing_removed(&owned, &state.client, &SECRETS.internal_api_key).await;
            StatusCode::OK
        }
        Some(_) => StatusCode::FORBIDDEN, // thats not not your listing buddY
        None => StatusCode::NOT_FOUND,
    }
}

#[utoipa::path(
    get,
    path = "/listings",
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "listing returned", body = Vec<FileListing>),
        (status = 500, description = "uhmmm...failed", body = String),
    ),
    tag = "file_listings"
)]
pub async fn get_listings(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Json<Vec<FileListing>> {
    let listings: Vec<FileListing> = state
        .files
        .iter()
        .filter(|l| match &l.visibility {
            Visibility::Private => l.owner_id == user.uuid,
            Visibility::Public => true,
            Visibility::Restricted { allowlist } => allowlist.contains(&user.uuid),
        })
        .map(|l| l.value().clone())
        .collect();
    Json(listings)
}

#[derive(Deserialize, ToSchema)]
pub struct RemoveSessionInput {
    pub session_id: Uuid,
}

#[utoipa::path(
    delete,
    path = "/listings/session",
    request_body = RemoveSessionInput,
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
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<RemoveSessionInput>,
) -> StatusCode {
    let to_remove: Vec<FileListing> = state
        .files
        .iter()
        .filter(|l| l.owner_id == user.uuid && l.session_id == req.session_id)
        .map(|l| l.value().clone())
        .collect();

    state.files.retain(|_, listing| {
        !(listing.owner_id == user.uuid && listing.session_id == req.session_id)
    });

    for listing in &to_remove {
        notify_listing_removed(listing, &state.client, &SECRETS.internal_api_key).await;
    }

    StatusCode::OK
}

async fn notify_listing_added(
    listing: &FileListing,
    client: &reqwest::Client,
    internal_api_key: &str,
) {
    let message = serde_json::json!({
        "namespace": "nanopass",
        "id": Uuid::new_v4(),
        "from_session_id": listing.session_id,
        "target_session_id": null,
        "payload": {
            "type": "ListingAdded",
            "listing": listing
        }
    });

    let url = match &listing.visibility {
        Visibility::Public => {
            "http://notification_backend:3003/internal/global_message".to_string()
        }
        Visibility::Private => format!(
            "http://notification_backend:3003/internal/user_message/{}",
            listing.owner_id
        ),
        Visibility::Restricted { .. } => {
            "http://notification_backend:3003/internal/global_message".to_string()
        }
    };

    let _ = client
        .post(url)
        .header("Authorization", format!("Basic {}", internal_api_key))
        .json(&message)
        .send()
        .await
        .map_err(|err| tracing::error!("failed to notify listing added: {}", err));
}

pub async fn notify_listing_removed(
    listing: &FileListing,
    client: &reqwest::Client,
    internal_api_key: &str,
) {
    let message = serde_json::json!({
        "namespace": "nanopass",
        "id": Uuid::new_v4(),
        "from_session_id": listing.session_id,
        "target_session_id": null,
        "payload": {
            "type": "ListingRemoved",
            "listing": listing
        }
    });

    let url = match &listing.visibility {
        Visibility::Public => {
            "http://notification_backend:3003/internal/global_message".to_string()
        }
        Visibility::Private => format!(
            "http://notification_backend:3003/internal/user_message/{}",
            listing.owner_id
        ),
        Visibility::Restricted { .. } => {
            "http://notification_backend:3003/internal/global_message".to_string()
        }
    };

    let _ = client
        .post(url)
        .header("Authorization", format!("Basic {}", internal_api_key))
        .json(&message)
        .send()
        .await
        .map_err(|err| tracing::error!("failed to notify listing added: {}", err));
}
