// This module handles JWT creation.
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::Serialize;  // Allows converting struct to JSON

use crate::errors::AppError;

// Claims - using standard JWT claim names
#[derive(Debug, Serialize)]
struct Claims {
    sub: i64,  // Subject: the user's ID
    exp: usize,  // Expiration: when the token expires (Unix timestamp)
    iat: usize,  // Issued at: when the token was created (Unix timestamp)
}

// Create a signed access token for the given user, using the provided
// secret and lifetime (in seconds).
pub fn create_access_token(
    user_id: i64,  // The user's database ID
    secret: &str,  // Secret key used to sign the token (must match when verifying)
    access_ttl_secs: i64,  // How long the token is valid (in seconds)
) -> Result<String, AppError> {
    // Get current time as Unix timestamp
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()  // This should never fail, but Rust requires handling the possibility
        .as_secs() as i64;

    // Create the claims (data inside the token)
    let claims = Claims {
        sub: user_id,  // User ID
        iat: now as usize,  // Issued at: current time
        exp: (now + access_ttl_secs) as usize,  // Expires at: current time + lifetime
    };

    // Encode the token: sign it with the secret key
    // This creates a string that looks like: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    encode(
        &Header::default(),  // Use default header (algorithm: HS256)
        &claims,  // The data to encode
        &EncodingKey::from_secret(secret.as_bytes()),  // Secret key for signing
    )
    // If encoding fails, convert to our custom error type
    .map_err(|_| AppError::BadRequest("Failed: Create access token".into()))
}
