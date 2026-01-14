use axum::{extract::State, Extension, Json};
use serde::Serialize;

use crate::{errors::AppError, state::AppState, auth::middleware::AuthenticationContext};

#[derive(Serialize)]
pub struct Profile {
    pub id: i64,
    pub username: String,
}

pub async fn get_profile(State(state): State<AppState>, Extension(ctx): Extension<AuthenticationContext>) -> Result<Json<Profile>, AppError> {
    let (id, username) = crate::database::get_user_by_id(&state.db, ctx.user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized("user not found".to_string()))?;

    Ok(Json(Profile { id, username }))
}
