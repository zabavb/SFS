// This module handles authentication endpoints: register, login, logout, refresh token.
// It validates user input, hashes passwords, and issues JWT tokens.

use axum::{extract::State, http::StatusCode, /* Extension,  */Json};
use serde::{Deserialize, Serialize};  // Deserialize = parse JSON, Serialize = convert to JSON

// Argon2 is a secure password hashing algorithm (better than MD5/SHA1)
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use sha2::{Digest, Sha256};  // SHA256 for hashing refresh tokens
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;  // Generate unique IDs for refresh tokens

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use argon2::password_hash::rand_core::OsRng;  // Random number generator for salts

use crate::{
    auth::jwt::create_access_token,
    errors::{is_username_uniqueness_violated, AppError},
    state::AppState,
};

// POST /login
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

// POST /login
#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,  // JWT token for API authentication (short-lived)
    pub refresh_token: String,  // Token to get new access tokens (long-lived)
    pub token_type: &'static str,  // Always "Bearer"
    pub expires_in: u64,  // Access token lifetime in seconds
}

// POST /register
#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

// POST /register
#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: i64,  // New user's database ID
    pub username: String,
}

// POST /token/refresh
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// POST /token/refresh
#[derive(Debug, Serialize)]
pub struct TokenPairResponse {
    pub access_token: String,  // New access token
    pub refresh_token: String,  // New refresh token (old one is revoked)
}

// POST /logout
#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

// Response structure for logout endpoints
#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub status: &'static str,  // Always "ok"
}

// POST /login
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    // Validate username format (same rules as registration)
    let username = validate_username(&payload.username)?;
    // Validate password format (same rules as registration for consistent error messages)
    validate_password(&payload.password)?;

    // Look up user in database by username
    let user = crate::database::get_user_by_username(&state.db, &username)
        .await?  // Wait for database query
        .ok_or_else(|| AppError::Unauthorized("invalid credentials".to_string()))?;  // Return error if user not found

    // Verify password matches stored hash
    // Parse the stored password hash
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| AppError::Internal("stored password hash invalid".to_string()))?;

    // Compare provided password with stored hash
    // If they don't match, return "invalid credentials" (don't reveal if username exists)
    Argon2::default()
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::Unauthorized("invalid credentials".to_string()))?;

    // Password is correct! Now issue tokens

    // Create access token (JWT) - short-lived token for API calls
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")  // Chaos, the world collapsed, so take money, yacht and buggati with you)
        .as_secs();
    let expires_in = state.config.access_ttl_secs as u64;
    let access_token =
        create_access_token(user.id, &state.config.jwt_secret, state.config.access_ttl_secs)?;

    // Create refresh token - long-lived token stored in database
    // Refresh tokens are UUIDs (random strings), not JWTs
    let refresh_token = Uuid::new_v4().to_string();
    let refresh_expires_at = (now as i64 + state.config.refresh_ttl_secs) as i64;

    // Hash the refresh token before storing (we never store plain tokens)
    // This way, even if database is compromised, tokens can't be used
    let mut hasher = Sha256::new();
    hasher.update(refresh_token.as_bytes());
    let refresh_hash_hex = hex::encode(hasher.finalize());

    // Store refresh token hash in database
    crate::database::insert_refresh_token(&state.db, user.id, &refresh_hash_hex, refresh_expires_at)
        .await?;

    // Return both tokens to the client
    Ok(Json(LoginResponse {
        access_token,
        refresh_token,  // Return plain token (hashed version is in DB)
        token_type: "Bearer",
        expires_in,
    }))
}

// POST /register
pub async fn register(
    State(state): State<AppState>,  // Access to database
    Json(payload): Json<RegisterRequest>,  // Parse JSON request body
) -> Result<(StatusCode, Json<RegisterResponse>), AppError> {
    // Validate username format
    let username = validate_username(&payload.username)?;
    // Validate password strength
    validate_password(&payload.password)?;
    let password = payload.password;

    // Hash password using Argon2 (secure password hashing algorithm)
    // Salt is random data added to make each hash unique (prevents rainbow table attacks)
    let salt = SaltString::generate(&mut OsRng);  // Generate random salt
    let argon2 = Argon2::default();  // Create Argon2 hasher
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)  // Hash password with salt
        .map_err(|e| AppError::Internal(format!("hashing failed: {e}")))?  // Convert error
        .to_string();  // Convert to string for storage

    // Insert new user into database
    let res = crate::database::insert_user(&state.db, &username, &password_hash).await;
    match res {
        // Success: return user ID and username
        Ok(id) => Ok((StatusCode::CREATED, Json(RegisterResponse { id, username }))),
        // Username already exists: return conflict error
        Err(e) if is_username_uniqueness_violated(&e) => {
            Err(AppError::Conflict("username already exists".to_string()))
        }
        // Other database error: return as-is
        Err(e) => Err(AppError::Db(e)),
    }
}

// Validate username format and length
// Returns cleaned username if valid, or an error if invalid
fn validate_username(raw: &str) -> Result<String, AppError> {
    // Remove leading/trailing whitespace
    let username = raw.trim().to_string();

    // Check length: must be between 3 and 32 characters
    if username.len() < 3 || username.len() > 32 {
        return Err(AppError::BadRequest(
            "username must be 3..32 characters long".to_string(),
        ));
    }

    // Check allowed characters: only letters, numbers, underscore, hyphen, and dot
    // .chars() iterates over each character
    // .all() returns true if ALL characters match the condition
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AppError::BadRequest(
            "username may contain only letters, digits, '_', '-' and '.'".to_string(),
        ));
    }

    Ok(username)
}

// Validate password strength requirements
// Returns Ok(()) if valid, or an error if invalid
fn validate_password(raw: &str) -> Result<(), AppError> {
    let password = raw;

    // Check length: must be between 8 and 128 characters
    if password.len() < 8 || password.len() > 128 {
        return Err(AppError::BadRequest(
            "password must be 8..128 characters long".to_string(),
        ));
    }

    // Check password complexity requirements:
    // - At least one lowercase letter (a-z)
    // - At least one uppercase letter (A-Z)
    // - At least one digit (0-9)
    // - At least one symbol (!@#$% etc.)
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace());

    // All requirements must be met
    if !(has_lower && has_upper && has_digit && has_symbol) {
        return Err(AppError::BadRequest(
            "password must contain at least one lowercase letter, one uppercase letter, \
one digit and one symbol"
                .to_string(),
        ));
    }

    Ok(())
}

// POST /token/refresh
pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<TokenPairResponse>, AppError> {
    // Step 1: Quick format validation (refresh token should be a UUID)
    // This catches obviously invalid tokens early
    if uuid::Uuid::parse_str(payload.refresh_token.trim()).is_err() {
        return Err(AppError::Unauthorized("invalid refresh token".into()));
    }

    // Step 2: Hash the token and look it up in database
    // We store hashed tokens, so we need to hash the provided token to compare
    let token_hash = crate::database::sha256_hex(payload.refresh_token.trim());
    let row = crate::database::get_refresh_token_by_hash(&state.db, &token_hash)
        .await?
        .ok_or_else(|| AppError::Unauthorized("invalid refresh token".into()))?;

    // Step 3: Validate token is not revoked and not expired
    let now = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
    };

    // Check if token was revoked (revoked_at is not None) or expired
    if row.revoked_at.is_some() || row.expires_at <= now {
        return Err(AppError::Unauthorized("refresh token expired".into()));
    }

    // Step 4: Token rotation - revoke the old refresh token
    // This prevents token reuse if someone steals it
    crate::database::revoke_refresh_token(&state.db, &token_hash, now).await?;

    // Step 5: Issue new tokens (both access and refresh)
    // Create new refresh token
    let new_refresh = crate::database::create_refresh_token(
        &state.db,
        row.user_id,
        state.config.refresh_ttl_secs,
    )
    .await?;

    // Create new access token
    let access = create_access_token(
        row.user_id,
        &state.config.jwt_secret,
        state.config.access_ttl_secs,
    )?;

    // Return new token pair
    Ok(Json(TokenPairResponse {
        access_token: access,
        refresh_token: new_refresh,
    }))
}

// POST /logout
pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, AppError> {
    // Validate UUID format (same validation as refresh endpoint)
    if uuid::Uuid::parse_str(payload.refresh_token.trim()).is_err() {
        return Err(AppError::BadRequest("invalid refresh token".into()));
    }

    // Try to revoke the token (hash it and mark as revoked in database)
    let affected = crate::database::revoke_refresh_token_by_raw(&state.db, payload.refresh_token.trim())
        .await?;

    // IMPORTANT: Always return "ok" regardless of whether token was found
    // This prevents "token enumeration" attacks - attackers can't tell if a token is valid
    // by checking the response (whether affected=0 or 1, client gets same response)
    let _ = affected;  // Ignore the result

    Ok(Json(LogoutResponse { status: "ok" }))
}