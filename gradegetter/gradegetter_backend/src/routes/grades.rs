use axum::{extract::State, Extension, Json};
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
        (status = 400, description = "No Grades"),
        (status = 401, description = "Credentials Incorrect"),
        (status = 403, description = "Role Mismatch"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "grades"
)]
pub async fn grades_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<Value>, axum::http::StatusCode> {
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

    let grades = match grades_row.map(|x| x.grades.unwrap()) {
        Some(grades) => grades,
        None => return Err(axum::http::StatusCode::BAD_REQUEST),
    };

    info!("Giving Grades to: {:?}", user.username);
    Ok(Json(grades))
}
