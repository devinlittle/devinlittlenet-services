use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use axum_prometheus::PrometheusMetricLayerBuilder;
use common::nanopass::{FileListing, NanoPassMessage, NanoPassPayload, Visibility};
use dashmap::DashMap;
use hyper::StatusCode;
use std::sync::Arc;
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::{
    middleware::{internal::basic_auth, jwt::jwt_auth},
    utils::secrets::SECRETS,
};

mod files;
mod internal;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::routes::health,
        crate::routes::files::create_listing,
        crate::routes::files::modify_listing,
        crate::routes::files::remove_listing,
        crate::routes::files::get_listings,
        crate::routes::files::remove_all_session_listings,
        crate::routes::internal::internal_remove_all_session_listings
    ),
    components(
        schemas(
            common::nanopass::RemoveListingInput,
            common::nanopass::RemoveSessionInput,
            common::nanopass::RemoveSessionInternalInput,
            common::nanopass::FileListingInput,
            common::nanopass::NanoPassMessage,
        )
    ),
    modifiers(&JwtBearer, &InternalAuth),
    tags(
        (name = "internal", description = "internal routes"),
        (name = "file_listings", description = "routes relating to file listings")
    )
)]
pub struct DaApiDoc;

struct JwtBearer;
struct InternalAuth;

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

impl utoipa::Modify for InternalAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "internal_auth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Basic).build()),
            );
        }
    }
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "returns 200 if service alive"),
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

impl AppState {
    pub async fn broadcast_nanopass_event(&self, listing: &FileListing, event: NanoPassPayload) {
        let message = NanoPassMessage {
            id: Uuid::new_v4(),
            namespace: common::Namespaces::NanoPass,
            from_session_id: None,
            from_user_id: None,
            target_user_id: Some(listing.owner_id),
            target_session_id: None,
            payload: event,
        };

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

        let _ = self
            .client
            .post(url)
            .header(
                "Authorization",
                format!("Basic {}", SECRETS.internal_api_key.as_str()),
            )
            .json(&message)
            .send()
            .await
            .map_err(|err| tracing::error!("failed to notify listing added: {}", err));
    }
}

pub fn create_routes() -> Router {
    let files = Arc::new(DashMap::new());

    let app_state = AppState {
        files,
        client: reqwest::Client::new(),
    };

    let (prometheus_layer, metric_handle) = PrometheusMetricLayerBuilder::new()
        .with_prefix("nanopass_backend")
        .with_default_metrics()
        .build_pair();

    let routes_without_middleware = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(|| async move { metric_handle.render() }));

    let routes_with_middleware = Router::new()
        .route(
            "/listings",
            post(files::create_listing)
                .delete(files::remove_listing)
                .get(files::get_listings)
                .patch(files::modify_listing),
        )
        .route(
            "/listings/session",
            delete(files::remove_all_session_listings),
        )
        .layer(middleware::from_fn_with_state(app_state.clone(), jwt_auth));

    let internal_routes = Router::new()
        .route(
            "/internal/session_cleanup",
            post(internal::internal_remove_all_session_listings),
        )
        .layer(middleware::from_fn(basic_auth));

    Router::new()
        .merge(routes_with_middleware)
        .merge(routes_without_middleware)
        .merge(internal_routes)
        .merge(SwaggerUi::new("/swegger-ui").url("/api-docs/openapi.json", DaApiDoc::openapi()))
        .with_state(app_state)
        .layer(prometheus_layer)
}
