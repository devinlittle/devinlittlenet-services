use axum::{
    extract::{Path, State},
    Json,
};
use hyper::StatusCode;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn get_user_roles(
    State(pool): State<PgPool>,
    Path(uuid): Path<Uuid>,
) -> Result<Json<Value>, StatusCode> {
    let roles = sqlx::query!("SELECT roles FROM users WHERE id = $1", uuid)
        .fetch_one(&pool)
        .await
        .map_err(|err| {
            tracing::error!("{}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .roles;
    Ok(Json(roles))
}
