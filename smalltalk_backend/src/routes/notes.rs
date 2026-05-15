use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use common::{
    smalltalk::{NoteCreateRequest, NotePatchRequest, SmalltalkNote, SmalltalkNotesEvent},
    AuthenticatedUser,
};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, QueryBuilder};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::routes::AppState;

#[derive(Serialize, Deserialize, ToSchema)]
pub struct NoteSyncParams {
    /// Unix timestamp in milliseconds
    #[schema(value_type = i64, example = 1715760000000_i64)]
    #[serde(with = "chrono::serde::ts_milliseconds")]
    pub since: DateTime<Utc>,
}

#[utoipa::path(
    get,
    path = "/notes",
    params(("since" = i64 , Query, description = "unix timestamp in milliseconds to grab notes after")),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "lists notes", body = Vec<SmalltalkNote>),
        (status = 401, description = "Credentials Incorrect"),
    ),
    tag = "smalltalk_notes"
)]
pub async fn note_sync(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Query(sync_params): Query<NoteSyncParams>,
) -> Result<Json<Vec<SmalltalkNote>>, StatusCode> {
    let synced_notes = sqlx::query_as!(
        SmalltalkNote,
        r#"
    SELECT
        id,
        user_id,
        enc_name,
        enc_content,
        is_protected as "is_protected!",
        password_hash,
        salt,
        rank as "rank!",
        is_deleted as "is_deleted!",
        updated_at as "updated_at!: chrono::DateTime<chrono::Utc>",
        created_at as "created_at!: chrono::DateTime<chrono::Utc>",
        last_accessed_at as "last_accessed_at!: chrono::DateTime<chrono::Utc>"
    FROM smalltalk_notes
    WHERE user_id = $1
    AND updated_at > $2::timestamptz
    ORDER BY updated_at ASC
    "#,
        user.uuid,
        sync_params.since as _ // have the "as _" because rust-analayzer doesn't like this line
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|err| {
        tracing::error!("Note sync database error: {:?}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(synced_notes))
}

// /notes grab_notes GET

//async fn grab_notes(State(state): State<AppState>, )

#[utoipa::path(
    post,
    path = "/note",
    request_body = NoteCreateRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "created note"),
        (status = 500, description = "internal server error"),
    ),
    tag = "smalltalk_notes"
)]
pub async fn create_note(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<NoteCreateRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut rb: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO smalltalk_notes (id, user_id, enc_name, is_protected, password_hash, salt, created_at, updated_at) VALUES ("
    );

    let mut separated = rb.separated(", ");

    separated.push("gen_random_uuid()"); // note id
    separated.push_bind(user.uuid);
    separated.push_bind(req.enc_name);

    separated.push_bind(req.is_protected);
    separated.push_bind(req.password_hash);
    separated.push_bind(req.salt);

    separated.push("NOW()"); // created_at
    separated.push("NOW()"); // updated_at

    rb.push(") RETURNING *");

    let query = rb.build_query_as::<SmalltalkNote>();
    let note = query.fetch_one(&state.pool).await.map_err(|err| {
        tracing::error!("Error creating note, {:?}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    state
        .broadcast_note_event(user.uuid, SmalltalkNotesEvent::NoteAdded { note })
        .await;

    Ok(StatusCode::OK)
}

#[utoipa::path(
    delete,
    path = "/note/{note_id}",
    params(
        ("note_id", description = "the id of the specific note to soft delete")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "updates note state and broadcasts update on websocket"),
        (status = 500, description = "internal server error"),
    ),
    tag = "smalltalk_notes"
)]
pub async fn soft_del_note(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(note_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let query = sqlx::query!(
        "UPDATE smalltalk_notes SET
            enc_content = NULL,
            is_deleted = TRUE
        WHERE id = $1 AND user_id = $2 RETURNING id",
        note_id,
        user.uuid
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|err| {
        tracing::error!("Error deleting note: {:?}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    state
        .broadcast_note_event(
            user.uuid,
            SmalltalkNotesEvent::NoteDeleted { note_id: query.id },
        )
        .await;

    Ok(StatusCode::OK)
}

#[utoipa::path(
    patch,
    path = "/note/{note_id}",
    request_body = NotePatchRequest,
    params(
        ("note_id", description = "the id of the specific note to update")
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "updates note and broadcasts update on websocket"),
        (status = 500, description = "internal server error"),
    ),
    tag = "smalltalk_notes"
)]
pub async fn update_note(
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(note_id): Path<Uuid>,
    Json(req): Json<NotePatchRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    match handle_patch_note(&state.pool, &note_id, &user.uuid, req).await {
        Ok(note) => {
            let event = SmalltalkNotesEvent::NoteUpdated { note_id, note };

            state.broadcast_note_event(user.uuid, event).await;

            Ok(StatusCode::OK)
        }
        Err(e) => {
            tracing::error!("Failed to patch note: {:?}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

pub async fn handle_patch_note(
    pool: &sqlx::PgPool,
    note_id: &Uuid,
    user_id: &Uuid,
    req: NotePatchRequest,
) -> Result<SmalltalkNote, sqlx::Error> {
    let mut rb: QueryBuilder<Postgres> = QueryBuilder::new("UPDATE smalltalk_notes SET ");
    let mut first = true;

    macro_rules! set {
        ($col:literal, $value:expr) => {{
            if !first {
                rb.push(", ");
            }
            first = false;
            rb.push(concat!($col, " = ")).push_bind($value);
        }};
    }

    if let Some(name) = req.enc_name {
        set!("enc_name", name);
    }

    if let Some(content) = req.enc_content {
        set!("enc_content", content);
    } else if req.is_deleted == Some(true) {
        if !first {
            rb.push(", ");
        }
        first = false;
        rb.push("enc_content = NULL");
    }

    if let Some(protected) = req.is_protected {
        set!("is_protected", protected);
    }

    if let Some(hash) = req.password_hash {
        set!("password_hash", hash);
    }

    if let Some(salt) = req.salt {
        set!("salt", salt);
    }

    if let Some(rank) = req.rank {
        set!("rank", rank);
    }

    if let Some(deleted) = req.is_deleted {
        set!("is_deleted", deleted);
    }

    if !first {
        rb.push(", ");
    }
    rb.push("updated_at = NOW()");

    rb.push(" WHERE id = ")
        .push_bind(note_id)
        .push(" AND user_id = ")
        .push_bind(user_id)
        .push(" RETURNING *");

    let query = rb.build_query_as::<SmalltalkNote>();
    let updated_note = query.fetch_one(pool).await?;

    Ok(updated_note)
}
