use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use axum_prometheus::PrometheusMetricLayerBuilder;
use common::smalltalk::{SmalltalkNotesEvent, SmalltalkNotesMessage};
use hyper::StatusCode;
use reqwest::Client;
use sqlx::PgPool;
use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;

use crate::utils::secrets::SECRETS;

pub mod internal;
pub mod notes;

#[derive(OpenApi)]
#[openapi(
      paths(
        crate::routes::health,
        crate::routes::notes::create_note,
        crate::routes::notes::note_sync,
        crate::routes::notes::update_note,
        crate::routes::notes::soft_del_note,
        // Internal Paths
        crate::routes::internal::invalidate_user,
        crate::routes::internal::delete_handler,
    ),
    components(
        schemas(
            common::AuthenticatedUser,
            common::Claims,
            common::smalltalk::SmalltalkNote,
            common::smalltalk::SmalltalkNotesMessage,
        )
    ),
    modifiers(&JwtBearer, &InternalAuth),
    tags(
        (name = "smalltalk_notes", description = "Endpoints relating to SmallTalk Notes"),
        (name = "internal", description = "Internal Endpoints")
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
        (status = 200, description = "returns 200 if service alive", body = String),
    ),
    tag = "internal"
)]
async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub seen_users: Arc<RwLock<HashSet<Uuid>>>,
    pub client: Client,
}

impl AppState {
    pub async fn broadcast_note_event(&self, user_id: Uuid, event: SmalltalkNotesEvent) {
        let message = SmalltalkNotesMessage {
            id: Uuid::new_v4(),
            namespace: common::Namespaces::SmallTalkNotes,
            payload: event,
        };

        let url = format!(
            "http://notification_backend:3003/internal/user_message/{}",
            user_id
        );

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

pub fn create_routes(pool: PgPool) -> Router {
    let (prometheus_layer, metric_handle) = PrometheusMetricLayerBuilder::new()
        .with_prefix("smalltalk_backend")
        .with_default_metrics()
        .build_pair();

    let seen_users = Arc::new(RwLock::new(HashSet::new()));
    let client = Client::new();

    let app_state = AppState {
        pool,
        seen_users,
        client,
    };

    let routes_without_middleware = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(|| async move { metric_handle.render() }));

    let routes_with_middleware = Router::new()
        .route("/notes", get(notes::note_sync))
        .route("/note", post(notes::create_note))
        .route(
            "/note/{note_id}",
            patch(notes::update_note).delete(notes::soft_del_note),
        )
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            crate::middleware::jwt::jwt_auth,
        ));

    let internal_routes = Router::new()
        .route(
            "/internal/invalidate/{uuid}",
            get(internal::invalidate_user),
        )
        .route("/internal/delete/{uuid}", delete(internal::delete_handler))
        .layer(axum::middleware::from_fn(
            crate::middleware::internal::basic_auth,
        ));

    Router::new()
        .merge(routes_with_middleware)
        .merge(internal_routes)
        .merge(routes_without_middleware)
        .merge(SwaggerUi::new("/swegger-ui").url("/api-docs/openapi.json", DaApiDoc::openapi()))
        .with_state(app_state)
        .layer(prometheus_layer)
}
