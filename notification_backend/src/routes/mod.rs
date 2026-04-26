use axum::{
    routing::{get, post},
    Router,
};
use axum_prometheus::PrometheusMetricLayerBuilder;
use dashmap::DashMap;
use hyper::StatusCode;
use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};
use tokio::sync::broadcast;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::middleware::jwt::jwt_auth;

mod internal;
mod noties;

#[derive(OpenApi)]
#[openapi(
      paths(
        crate::routes::health,
        crate::routes::noties::notify,
    ),
    components(
        schemas(
            crate::utils::jwt::AuthenticatedUser,
            crate::utils::jwt::Claims,
        )
    ),
    modifiers(&JwtBearer),
    tags(
        (name = "ws", description = "The websocket")
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

type ConnectedUsers = Arc<DashMap<Uuid, broadcast::Sender<String>>>;
type OnlineUsers = Arc<DashMap<Uuid, Arc<RwLock<HashSet<Uuid>>>>>;

#[derive(Clone)]
pub struct AppState {
    pub connected_users: ConnectedUsers,
    pub global_channel: Arc<broadcast::Sender<String>>,
    pub online_users: OnlineUsers,
}

pub fn create_routes() -> Router {
    let connected_users = Arc::new(DashMap::new());

    let (global_tx, _) = broadcast::channel::<String>(32);
    let global_channel = Arc::new(global_tx);

    let online_users: OnlineUsers = Arc::new(DashMap::new());

    let app_state = AppState {
        connected_users,
        global_channel,
        online_users,
    };

    let (prometheus_layer, metric_handle) = PrometheusMetricLayerBuilder::new()
        .with_prefix("notification_backend")
        .with_default_metrics()
        .build_pair();

    let routes_without_middleware = Router::new()
        .route("/health", get(health))
        .route("/ws/{uuid}", get(noties::notify))
        .route("/metrics", get(|| async move { metric_handle.render() }));

    let routes_with_middleware = Router::new()
        .route("/user_message/{uuid}", post(noties::user_message))
        .layer(axum::middleware::from_fn(jwt_auth));

    let internal_routes = Router::new()
        .route("/internal/global_message", post(internal::global_message))
        .route(
            "/internal/user_message/{uuid}",
            post(internal::user_message),
        )
        .layer(axum::middleware::from_fn(
            crate::middleware::internal::basic_auth,
        ));

    Router::new()
        .merge(routes_with_middleware)
        .merge(routes_without_middleware)
        .merge(internal_routes)
        .merge(SwaggerUi::new("/swegger-ui").url("/api-docs/openapi.json", DaApiDoc::openapi()))
        .with_state(app_state)
        .layer(prometheus_layer)
}
