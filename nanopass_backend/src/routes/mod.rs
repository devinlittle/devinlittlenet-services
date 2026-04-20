use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use dashmap::DashMap;
use hyper::StatusCode;
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::{
    middleware::{internal::basic_auth, jwt::jwt_auth},
    utils::structs::FileListing,
};

mod files;
mod internal;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::health,
        crate::routes::files::create_listing,
        crate::routes::files::remove_listing,
        crate::routes::files::get_listings,
        crate::routes::files::remove_all_session_listings,
        crate::routes::internal::remove_all_session_listings
    ),
    components(
        schemas(
            crate::middleware::jwt::AuthenticatedUser,
            crate::middleware::jwt::Claims,
            crate::routes::files::RemoveListingInput,
            crate::routes::files::RemoveSessionInput,
            crate::utils::structs::FileListingInput,
            crate::routes::internal::RemoveSessionInternalInput,
        )
    ),
    modifiers(&JwtBearer),
    tags(
        (name = "internal", description = "internal routes"),
        (name = "file_listings", description = "routes relating to file listings")
    )
)]
pub struct DaApiDoc;

struct JwtBearer;

impl utoipa::Modify for JwtBearer {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    ),
                ),
            )
        }
    }
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "returns 200 if service alive", body = String),
    ),
    tag = "internal"
)]
async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(Clone)]
pub struct AppState {
    pub files: Arc<DashMap<Uuid, FileListing>>,
    pub client: reqwest::Client,
}

pub fn create_routes() -> Router {
    let files = Arc::new(DashMap::new());

    let app_state = AppState {
        files,
        client: reqwest::Client::new(),
    };

    let routes_without_middleware = Router::new().route("/health", get(health));

    let routes_with_middleware = Router::new()
        .layer(middleware::from_fn(jwt_auth))
        .route(
            "/listings",
            post(files::create_listing)
                .delete(files::remove_listing)
                .get(files::get_listings),
        )
        .route(
            "/listings/session",
            delete(files::remove_all_session_listings),
        )
        .layer(middleware::from_fn_with_state(app_state.clone(), jwt_auth));

    let internal_routes = Router::new()
        .route(
            "/internal/session_cleanup",
            post(internal::remove_all_session_listings),
        )
        .layer(middleware::from_fn(basic_auth));

    Router::new()
        .merge(routes_with_middleware)
        .merge(routes_without_middleware)
        .merge(internal_routes)
        .merge(SwaggerUi::new("/swegger-ui").url("/api-docs/openapi.json", DaApiDoc::openapi()))
        .with_state(app_state)
}
