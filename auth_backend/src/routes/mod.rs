use axum::{
    routing::{delete, get, post},
    Router,
};
use sqlx::PgPool;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub mod auth;
pub mod internal;

#[derive(OpenApi)]
#[openapi(
      paths(
        // Auth paths
        crate::routes::auth::register_handler,
        crate::routes::auth::login_handler,
        crate::routes::auth::logout_handler,
        crate::routes::auth::refresh_handler,
        crate::routes::auth::delete_handler,
        crate::routes::auth::health,
    ),
    components(
        schemas(
            crate::routes::auth::RegisterInput,
            crate::routes::auth::LoginInput,
            crate::middleware::jwt::AuthenticatedUser,
            crate::middleware::jwt::Claims,
        )
    ),
    modifiers(&JwtBearer),
    tags(
        (name = "user_auth", description = "Authentication endpoints"),
        (name = "internal", description = "internal routes only meant for use between services"),
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

pub fn create_routes(pool: PgPool) -> Router {
    let routes_without_middleware = Router::new()
        .route("/register", post(auth::register_handler))
        .route("/login", post(auth::login_handler))
        .route("/refresh", post(auth::refresh_handler))
        .route("/logout", get(auth::logout_handler))
        .route("/health", get(auth::health));

    let routes_with_middleware = Router::new()
        .route("/delete", delete(auth::delete_handler))
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
}
