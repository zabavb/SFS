use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{errors::AppError, auth::middleware::AuthenticationContext, state::AppState};

use axum::{
    body::Body,
    extract::{Multipart, State, Path},
    http::{header, HeaderValue, StatusCode},
    response::Response,
    Extension, Json,
};
use tokio_util::io::ReaderStream;
use std::path::PathBuf;

// POST /file/upload
#[derive(Serialize)]
pub struct UploadFile {
    pub id: String,
    pub name: String,
    pub bytes: u64,
    pub extension: Option<String>,
    pub is_public: bool,
}

// POST /file/:id/share
#[derive(Debug, Deserialize)]
pub struct ShareFileRequest {
    pub username: String,
}

// POST /file/:id/share
#[derive(Debug, Serialize)]
pub struct ShareFileResponse {
    pub user_username: String,
    pub file_id: String,
}

// DELETE /file/:id/share/:username
#[derive(Debug, Serialize)]
pub struct RevokeFile {
    pub user_username: String,
    pub file_id: String,
}

// POST/DELETE /file/:id/public
#[derive(Debug, Serialize)]
pub struct FileAccessStatus {
    pub file_id: String,
    pub is_public: bool,
}


// POST /file/upload
pub async fn upload_file(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthenticationContext>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<UploadFile>), AppError> {
    let mut field = loop {
        match multipart
            .next_field()
            .await
            .map_err(|e| AppError::BadRequest(format!("invalid file: {e}")))? 
        {
            Some(f) if f.name() == Some("file") => break f, // Found -> return
            Some(_) => continue,               // Skip
            None => return Err(AppError::BadRequest("missing 'file' field".into())),
        }
    };

    let file_name = field
        .file_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown_file.bin".to_string());

    let extension = field.content_type().map(|e| e.to_string());

    let id = Uuid::new_v4().to_string();

    let tmp_path = state.config.files_path.join(format!("{id}.chunk"));
    let path = state.config.files_path.join(&id);

    let mut out = tokio::fs::File::create(&tmp_path)
        .await
        .map_err(|e| AppError::Internal(format!("create upload file failed: {e}")))?;

    let mut size: u64 = 0;  // Track file size

    // Read file by chunks/parts
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| AppError::BadRequest(format!("read upload chunk failed: {e}")))? 
    {
        size += chunk.len() as u64;

        // Upload chunk to temp storage
        out.write_all(&chunk)
            .await
            .map_err(|e| AppError::Internal(format!("write upload failed: {e}")))?;
    }

    // Flush any remaining data to temp storage
    out.flush()
        .await
        .map_err(|e| AppError::Internal(format!("flush upload failed: {e}")))?;
    drop(out);

    // Atomically rename from .chunk to final name
    tokio::fs::rename(&tmp_path, &path)
        .await
        .map_err(|e| AppError::Internal(format!("finalize upload failed: {e}")))?;

    let result_path = path.to_string_lossy().to_string();


    if let Err(e) = crate::database::insert_file(
        &state.db,
        &id,
        ctx.user_id,  // File owner
        &file_name,
        &result_path,
        size as i64,
        extension.as_deref(),
    )
    .await
    {
        // Delete file if database insert failed
        let _ = tokio::fs::remove_file(&result_path).await;
        return Err(AppError::Db(e));
    }

    Ok((
        StatusCode::CREATED,
        Json(UploadFile {
            id,
            name: file_name,
            bytes: size,
            extension,
            is_public: false,  // New files are private by default
        }),
    ))
}

/* // GET /files
pub async fn list_files(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,  // Current user
) -> Result<Json<Vec<FileSummary>>, AppError> {
    // Get all files owned by this user from database
    let files = crate::db::list_files_for_owner(&state.db, ctx.user_id).await?;

    // Convert database records to response format
    // .into_iter() = convert to iterator
    // .map() = transform each file
    // .collect() = collect into a Vec
    let summaries = files
        .into_iter()
        .map(|f| FileSummary {
            id: f.id,
            name: f.original_name,
            size_bytes: f.size_bytes,
            is_public: f.is_public == 1,  // SQLite stores booleans as 0/1
        })
        .collect();

    Ok(Json(summaries))
} */

// GET /file/:id
pub async fn download_file(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthenticationContext>,  // Current user
    Path(file_id): Path<String>,  // File ID from URL
) -> Result<Response, AppError> {
    // Step 1: Load file metadata from database
    let db_file = crate::database::get_file_by_id(&state.db, &file_id)
        .await?
        .ok_or(AppError::NotFound)?;  // Return 404 if file doesn't exist

    let is_public = db_file.is_public == 1;

    // Step 2: Check if user has permission to download this file
    // Security: return NotFound (not Forbidden) to prevent information leakage
    let is_allowed = if db_file.user_id == ctx.user_id || is_public {
        // User owns the file OR file is public
        true
    } else {
        // Check if file was shared with this user
        crate::database::has_file_permission(&state.db, &file_id, ctx.user_id).await?
    };

    // If not allowed, return NotFound (not Forbidden) for security
    if !is_allowed {
        return Err(AppError::NotFound);
    }

    // Step 3: Open file before starting response (fail early if file missing)
    let path = PathBuf::from(&db_file.storage_path);
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| AppError::NotFound)?;  // Return 404 if file not on disk

    // Step 4: Stream file with backpressure (efficient for large files)
    // ReaderStream reads file in chunks, preventing memory issues
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    // Step 5: Build HTTP response headers BEFORE streaming begins
    // Content-Type tells browser what kind of file this is
    let content_type = db_file.extension.clone().unwrap_or_else(|| "application/octet-stream".to_string());

    // Sanitize filename for HTTP header safety (remove dangerous characters)
    let safe_name = db_file.name.replace('"', "").replace("\r", "").replace("\n", "");
    // Content-Disposition tells browser to download file with this name
    let disposition = format!("attachment; filename=\"{}\"", safe_name);

    // Create HTTP response
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;

    // Set response headers
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type).unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).unwrap_or(HeaderValue::from_static("attachment")),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&db_file.bytes.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );

    Ok(response)
}

// POST /file/:id/share
pub async fn share_file(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthenticationContext>,  // Current user
    Path(file_id): Path<String>,  // File ID from URL
    Json(payload): Json<ShareFileRequest>,  // Username to share with
) -> Result<(StatusCode, Json<ShareFileResponse>), AppError> {
    // Step 1: File must exist
    let file = crate::database::get_file_by_id(&state.db, &file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Step 2: Only the file owner can share it
    if file.user_id != ctx.user_id {
        return Err(AppError::Forbidden("only file owner can share this file".into()));
    }

    // Step 3: Target user must exist
    let target_username = payload.username.trim().to_string();
    if target_username.is_empty() {
        return Err(AppError::BadRequest("username is required".into()));
    }

    // Look up target user by username
    let target_user_id: i64 = crate::database::get_user_id_by_username(&state.db, &target_username)
        .await?
        .ok_or_else(|| AppError::BadRequest("target user not found".into()))?;

    // Step 4: Prevent sharing to yourself (optional security check)
    if target_user_id == ctx.user_id {
        return Err(AppError::BadRequest("cannot share file to yourself".into()));
    }

    // Step 5: Insert permission (grant access to target user)
    // insert_permission uses INSERT OR IGNORE, so affected=0 means already shared
    let affected = crate::database::insert_permission(&state.db, &file_id, target_user_id).await?;
    if affected == 0 {
        return Err(AppError::BadRequest("already shared with this user".into()));
    }

    Ok((
        StatusCode::OK,
        Json(ShareFileResponse {
            user_username: target_username,
            file_id,
        }),
    ))
}

// DELETE /file/:id/share/:username
pub async fn revoke_share(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthenticationContext>,  // Current user
    Path((file_id, username)): Path<(String, String)>,  // File ID and username from URL
) -> Result<(StatusCode, Json<RevokeFile>), AppError> {
    // Step 1: File must exist
    let file = crate::database::get_file_by_id(&state.db, &file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Step 2: Only the file owner can revoke sharing
    if file.user_id != ctx.user_id {
        return Err(AppError::Forbidden("only file owner can revoke sharing".into()));
    }

    // Step 3: Target user must exist
    let user_username = username.trim().to_string();
    if user_username.is_empty() {
        return Err(AppError::BadRequest("username is required".into()));
    }

    // Look up target user by username
    let user_id = crate::database::get_user_id_by_username(&state.db, &user_username)
        .await?
        .ok_or_else(|| AppError::BadRequest("file receiver not found".into()))?;

    // Step 4: Delete permission (revoke access)
    let affected = crate::database::delete_permission(&state.db, &file_id, user_id).await?;
    if affected == 0 {
        return Err(AppError::BadRequest("user does not currently have access".into()));
    }

    Ok((
        StatusCode::OK,
        Json(RevokeFile {
            user_username: user_username,
            file_id,
        }),
    ))
}

// POST /file/:id/public
pub async fn make_public(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthenticationContext>,  // Current user
    Path(file_id): Path<String>,  // File ID from URL
) -> Result<(StatusCode, Json<FileAccessStatus>), AppError> {
    // Load file metadata
    let file = crate::database::get_file_by_id(&state.db, &file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Only the file owner can change public setting
    if file.user_id != ctx.user_id {
        return Err(AppError::Forbidden("only owner can change public file".into()));
    }

    // Update database: set is_public = true
    crate::database::make_file_public_or_private(&state.db, &file_id, true).await?;

    Ok((
        StatusCode::OK,
        Json(FileAccessStatus {
            file_id,
            is_public: true,
        }),
    ))
}

// DELETE /file/:id/public
pub async fn make_private(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthenticationContext>,  // Current user
    Path(file_id): Path<String>,  // File ID from URL
) -> Result<(StatusCode, Json<FileAccessStatus>), AppError> {
    // Load file metadata
    let file = crate::database::get_file_by_id(&state.db, &file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Only the file owner can change public setting
    if file.user_id != ctx.user_id {
        return Err(AppError::Forbidden("only owner can change public file".into()));
    }

    // Update database: set is_public = false
    crate::database::make_file_public_or_private(&state.db, &file_id, false).await?;

    Ok((
        StatusCode::OK,
        Json(FileAccessStatus {
            file_id,
            is_public: false,
        }),
    ))
}

// GET /file/public/:id
pub async fn download_public_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,  // File ID from URL
) -> Result<Response, AppError> {
    // Load file metadata from database
    let db_file = crate::database::get_file_by_id(&state.db, &file_id)
        .await?
        .ok_or(AppError::NotFound)?;

    // Security check: Only public files can be downloaded without authentication
    // Return NotFound (not Forbidden) to prevent information leakage
    if db_file.is_public != 1 {
        return Err(AppError::NotFound);
    }

    // Open file from disk
    let path = std::path::PathBuf::from(&db_file.storage_path);
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| AppError::NotFound)?;

    // Stream file efficiently
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    // Set content type
    let content_type = db_file
        .extension
        .clone()
        .unwrap_or_else(|| "application/octet-stream".to_string());

    // Sanitize filename for HTTP header
    let name = db_file.name.replace('"', "").replace("\r", "").replace("\n", "");
    let disposition = format!("attachment; filename=\"{}\"", name);

    // Build HTTP response
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;

    use axum::http::header;
    use axum::http::HeaderValue;

    // Set response headers
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition).unwrap_or(HeaderValue::from_static("attachment")),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&db_file.bytes.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );

    Ok(response)
}
