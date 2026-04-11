use axum::{extract::State, Extension, Json};
use crypto_utils::decrypt_string;
use hyper::StatusCode;
use serde_json::Value;
use tracing::info;

use crate::{middleware::jwt::AuthenticatedUser, routes::AppState};

#[utoipa::path(
    get,
    path = "/grades",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Grades for the User", body = Value),
        (status = 401, description = "Credentials Incorrect"),
        (status = 403, description = "Role Mismatch"),
        (status = 404, description = "No Grades Found"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "grades"
)]
pub async fn grades_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<Value>, StatusCode> {
    if user.role != "devin" && user.role != "trusted" {
        return Err(StatusCode::FORBIDDEN);
    }

    let grades_row = sqlx::query!("SELECT grades FROM grades WHERE id = $1", user.uuid)
        .fetch_optional(&state.pool)
        .await
        .map_err(|err| {
            tracing::info!("Database error: {}", err);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let encrypted_grades = match grades_row {
        Some(encrypted_grades) => encrypted_grades,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let grades = decrypt_string(encrypted_grades.grades.as_str()).map_err(|err| {
        tracing::error!("failed to decrypt grades: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let grades: serde_json::Value = serde_json::from_str(&grades).map_err(|err| {
        tracing::error!("failed to parse grades JSON: {}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Giving Grades to: {:?}", user.username);
    Ok(Json(grades))
}
