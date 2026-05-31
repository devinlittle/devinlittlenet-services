use axum::{extract::State, Extension, Json};
use crypto_utils::decrypt_string;
use hyper::StatusCode;
use tracing::{error, info, info_span, instrument, warn, Instrument};

use crate::routes::AppState;

use common::{gradegetter::GradesHashMap, AuthenticatedUser};

#[instrument(
    name = "fetch_grades",
    skip(state),
    fields(
        user.username = %user.username,
        user.id = %user.uuid,
        user.session_id = %user.session_id,
    )
)]
#[utoipa::path(
    get,
    path = "/grades",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Grades for the User", body = GradesHashMap),
        (status = 401, description = "Credentials Incorrect"),
        (status = 404, description = "No Grades Found"),
        (status = 500, description = "Interal Server Error")
    ),
    tag = "grades"
)]
pub async fn grades_handler(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<GradesHashMap>, StatusCode> {
    let db_span = info_span!("grades_query");

    let grades_row = sqlx::query!("SELECT grades FROM grades WHERE id = $1", user.uuid)
        .fetch_optional(&state.pool)
        .instrument(db_span)
        .await
        .map_err(|err| {
            error!(error = %err, "[Database failure]: failed to grab grade info from db");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let encrypted_grades = match grades_row {
        Some(encrypted_grades) => encrypted_grades,
        None => {
            warn!(
                action = "gradegetter_backend.fetch_grades",
                user.id = %user.uuid,
                user.username = %user.username,
                "Grades Not Found"
            );

            return Err(StatusCode::NOT_FOUND);
        }
    };

    let grades = decrypt_string(encrypted_grades.grades).map_err(|err| {
        error!(error = %err, "[Encryption Error]: failed to encrypt password");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let grades: GradesHashMap = serde_json::from_str(&grades).map_err(|err| {
        error!(error = %err, "[Encryption Error]: failed to parse grades JSON");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!(
        action = "gradegetter_backend.fetch_grades",
        user.id = %user.uuid,
        user.username = %user.username,
        "Gave grades to user",
    );

    Ok(Json(grades))
}
