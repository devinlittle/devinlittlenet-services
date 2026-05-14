use axum::{extract::State, response::IntoResponse, Extension, Json};
use chrono::Utc;
use hyper::StatusCode;
use uuid::Uuid;

use crate::routes::AppState;

use common::{
    nanopass::{FileListing, FileListingInput, RemoveListingInput, RemoveSessionInput, Visibility},
    AuthenticatedUser,
};

#[utoipa::path(
    get,
    path = "/listings",
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "listing returned", body = Vec<FileListing>),
        (status = 500, description = "uhmmm...failed"),
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
            Visibility::Restricted { allowlist } => {
                allowlist.contains(&user.uuid) || l.owner_id == user.uuid
            }
        })
        .map(|l| l.value().clone())
        .collect();
    Json(listings)
}

#[utoipa::path(
    post,
    path = "/listings",
    request_body = FileListingInput,
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "listing created", body = FileListing),
        (status = 500, description = "uhmmm...failed"),
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
        owner_username: user.username.clone(),
        session_id: req.session_id,
        filename: req.filename,
        size_bytes: req.size_bytes,
        mime_type: req.mime_type,
        created_at: Utc::now(),
        visibility: req.visibility,
        auto_accept: req.auto_accept,
    };

    if state
        .files
        .insert(file_listing.id, file_listing.clone())
        .is_none()
    {
        state
            .broadcast_nanopass_event(
                &file_listing,
                common::nanopass::NanoPassPayload::ListingAdded {
                    listing: file_listing.clone(),
                },
            )
            .await;
        tracing::info!("{} added a new listing", &user.username);
        Json(file_listing).into_response()
    } else {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

#[utoipa::path(
    patch,
    path = "/listings",
    request_body = FileListing,
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "listing modified"),
        (status = 500, description = "uhmmm...failed"),
    ),
    tag = "file_listings"
)]
pub async fn modify_listing(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<FileListing>,
) -> StatusCode {
    match state.files.get(&req.id) {
        Some(listing) if listing.owner_id == user.uuid => {
            let owned = req.clone();
            drop(listing);
            state.files.alter(&owned.id, |_, _| req);

            state
                .broadcast_nanopass_event(
                    &owned,
                    common::nanopass::NanoPassPayload::ListingModified {
                        listing: owned.clone(),
                    },
                )
                .await;

            tracing::info!("{} motified a listing", &user.username);
            StatusCode::OK
        }
        Some(_) => StatusCode::FORBIDDEN, // thats not not your listing buddY
        None => StatusCode::NOT_FOUND,
    }
}

#[utoipa::path(
    delete,
    path = "/listings",
    request_body = RemoveListingInput,
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "listing removed"),
        (status = 500, description = "uhmmm...failed"),
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

            state
                .broadcast_nanopass_event(
                    &owned,
                    common::nanopass::NanoPassPayload::ListingRemoved {
                        listing: owned.clone(),
                    },
                )
                .await;

            tracing::info!("{} removed a listing", &user.username);
            StatusCode::OK
        }
        Some(_) => StatusCode::FORBIDDEN, // thats not not your listing buddY
        None => StatusCode::NOT_FOUND,
    }
}

#[utoipa::path(
    delete,
    path = "/listings/session",
    request_body = RemoveSessionInput,
    security(
        ("bearer_auth" = []),
    ),
    responses(
        (status = 200, description = "all listing removed from a specific session_id"),
        (status = 500, description = "uhmmm...failed"),
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
        state
            .broadcast_nanopass_event(
                listing,
                common::nanopass::NanoPassPayload::ListingRemoved {
                    listing: listing.clone(),
                },
            )
            .await
    }

    tracing::info!("{} removed their listings", &user.username);
    StatusCode::OK
}
