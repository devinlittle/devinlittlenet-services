use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use axum_prometheus::PrometheusMetricLayerBuilder;
use sqlx::PgPool;
use utoipa::{
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
    OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

mod admin;
mod auth;
mod internal;
mod user;

#[derive(OpenApi)]
#[openapi(
      paths(
        // Auth paths
        crate::routes::auth::register_handler,
        crate::routes::auth::login_handler,
        crate::routes::auth::logout_handler,
        crate::routes::auth::refresh_handler,
        crate::routes::auth::health,
        // User Routes
        crate::routes::user::add_publickey,
        crate::routes::user::delete_handler,
        crate::routes::user::list_active_sessions,
        crate::routes::user::revoke_specific_session,
        crate::routes::user::revoke_all_sessions,
        crate::routes::user::add_recovery_info,
        crate::routes::user::verify_recovery_info,
        crate::routes::user::search_user,
        // Admin Paths
        crate::routes::admin::list_users,
        crate::routes::admin::change_role,
        crate::routes::admin::revoke_all_from_id,
        crate::routes::admin::evict_from_hashset,
        // Internal Paths
        crate::routes::internal::get_user_roles
    ),
    components(
        schemas(
            crate::routes::auth::RegisterInput,
            crate::routes::auth::LoginInput,
            crate::routes::user::UpdateProfileInput,
            crate::routes::user::AddRecoveryInfoInputs,
            crate::routes::user::VerifyRecoveryInfoInputs,
            crate::routes::user::VerifyRecoveryInfoOutputs,
            crate::routes::user::UserSearchResult,
            crate::middleware::jwt::AuthenticatedUser,
            crate::middleware::jwt::Claims,
        )
    ),
    modifiers(&JwtBearer, &CookieAuth, &InternalAuth),
    tags(
        (name = "user_auth", description = "Authentication endpoints"),
        (name = "internal", description = "internal routes only meant for use between services"),
    )
)]
pub struct DaApiDoc;

struct JwtBearer;
struct CookieAuth;
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

impl utoipa::Modify for CookieAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "cookie_auth",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("refresh_token"))),
            );
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

pub fn create_routes(pool: PgPool) -> Router {
    let (prometheus_layer, metric_handle) = PrometheusMetricLayerBuilder::new()
        .with_prefix("auth_backend")
        .with_default_metrics()
        .build_pair();

    let routes_without_middleware = Router::new()
        .route("/register", post(auth::register_handler))
        .route("/login", post(auth::login_handler))
        .route("/refresh", post(auth::refresh_handler))
        .route("/logout", get(auth::logout_handler))
        .route("/metrics", get(|| async move { metric_handle.render() }))
        .route("/health", get(auth::health));

    let routes_with_middleware = Router::new()
        // User Routes
        .route(
            "/me",
            patch(user::add_publickey).delete(user::delete_handler),
        )
        .route(
            "/me/sessions",
            get(user::list_active_sessions).delete(user::revoke_all_sessions),
        )
        .route("/me/session/{id}", delete(user::revoke_specific_session))
        .route("/me/recovery", patch(user::add_recovery_info))
        .route("/me/recovery/verify", post(user::verify_recovery_info))
        .route("/users/search", get(user::search_user))
        //Admin Routes
        .route("/admin/users", get(admin::list_users))
        .route("/admin/users/{id}/role", patch(admin::change_role))
        .route("/admin/users/{id}/evict", post(admin::evict_from_hashset))
        .route("/admin/users/{id}/delete", delete(admin::delete_by_id))
        .route("/admin/revoke_all/{id}", delete(admin::revoke_all_from_id))
        .route("/admin/global_message", post(admin::global_message))
        .layer(axum::middleware::from_fn(crate::middleware::jwt::jwt_auth));

    let internal_routes = Router::new()
        .route(
            "/internal/users/{uuid}/roles",
            get(internal::get_user_roles),
        )
        .layer(axum::middleware::from_fn(
            crate::middleware::internal::basic_auth,
        ));

    Router::new()
        .merge(routes_with_middleware)
        .merge(internal_routes)
        .merge(routes_without_middleware)
        .merge(SwaggerUi::new("/swegger-ui").url("/api-docs/openapi.json", DaApiDoc::openapi()))
        .with_state(pool)
        .layer(prometheus_layer)
}
