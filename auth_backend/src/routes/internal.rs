use axum::{
    extract::{Path, State},
    Json,
};
use common::UserRoles;
use hyper::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

#[utoipa::path(
    get,
    path = "/internal/users/{uuid}/roles",
    params(
        ("uuid", description = "pretty easy to understand what this means.")
    ),
    security(
        ("internal_auth" = []),
    ),
    responses(
        (status = 200, description = "sends back in json the users roles", body = String),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "internal"
)]
pub async fn get_user_roles(
    State(pool): State<PgPool>,
    Path(uuid): Path<Uuid>,
) -> Result<Json<UserRoles>, StatusCode> {
    let row = sqlx::query!("SELECT roles FROM users WHERE id = $1", uuid)
        .fetch_one(&pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => StatusCode::NOT_FOUND,
            _ => {
                tracing::error!("Database error fetching roles: {}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;

    let roles: UserRoles = serde_json::from_value(row.roles).map_err(|e| {
        tracing::error!("Failed to deserialize UserRoles for {}: {}", uuid, e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(roles))
}

// TODO: add route to update active to true
