use axum::{
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use hyper::StatusCode;
use sqlx::PgPool;
use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};
use tokio::sync::{broadcast, watch};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

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
    tags(
        (name = "ws", description = "The websocket")
    )
)]
pub struct DaApiDoc;

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
    pub connected_users: Arc<DashMap<Uuid, broadcast::Sender<String>>>,
    pub global_channel: Arc<broadcast::Sender<String>>,
}

pub fn create_routes() -> Router {
    let connected_users = Arc::new(DashMap::new());

    let (global_tx, _) = broadcast::channel::<String>(32);
    let global_channel = Arc::new(global_tx);

    let app_state = AppState {
        connected_users,
        global_channel,
    };

    let routes_without_middleware = Router::new()
        .route("/health", get(health))
        .route("/ws/{uuid}", get(noties::notify));

    let routes_with_middleware = Router::new();

    Router::new()
        .merge(routes_with_middleware)
        .merge(routes_without_middleware)
        .merge(SwaggerUi::new("/swegger-ui").url("/api-docs/openapi.json", DaApiDoc::openapi()))
        .with_state(app_state)
}
